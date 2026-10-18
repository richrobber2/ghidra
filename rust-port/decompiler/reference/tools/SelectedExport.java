// SPDX-License-Identifier: Apache-2.0
// @category Analysis
// Export a bounded, explicitly selected function set without automatic analysis.
// Args: SPECS_JSON OUTPUT_DIR DECOMPILE_TIMEOUT_SECONDS
// SPECS_JSON: [{"label":"name", "image_offset_hex":"0x19c60", "size":531}]
// or absolute {"label":"name", "address_hex":"0x...", "size":531}.
// Optional per-row set_body_to_requested_extent:true replaces an imported stub's
// existing function body with this explicit extent. Default false preserves it.

import java.io.BufferedWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.CancelledException;

public class SelectedExport extends HeadlessScript {
    private static final long MAX_TARGET_BYTES = 16L * 1024 * 1024;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private static BigInteger parseUnsignedHex(String value) {
        String text = value.trim();
        if (text.startsWith("0x") || text.startsWith("0X")) text = text.substring(2);
        BigInteger result = new BigInteger(text, 16);
        if (result.signum() < 0 || result.bitLength() > 64) {
            throw new IllegalArgumentException("Hex offset must be an unsigned 64-bit value");
        }
        return result;
    }

    private static String hexBytes(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) text.append(String.format("%02x", value & 0xff));
        return text.toString();
    }

    private static List<Map<String, Object>> ranges(AddressSetView set) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (AddressRange range : set) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("start", range.getMinAddress().toString());
            row.put("end_inclusive", range.getMaxAddress().toString());
            row.put("size_bytes", range.getLength());
            result.add(row);
        }
        return result;
    }

    private static Map<String, Object> symbolRow(Symbol symbol) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", symbol.getName());
        row.put("qualified_name", symbol.getName(true));
        row.put("address", symbol.getAddress().toString());
        row.put("symbol_type", symbol.getSymbolType().toString());
        row.put("source", symbol.getSource().toString());
        row.put("primary", symbol.isPrimary());
        return row;
    }

    private List<Map<String, Object>> originalSymbols(Address start, Address end)
            throws CancelledException {
        List<Map<String, Object>> result = new ArrayList<>();
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbolIterator(start, true);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            Address address = symbol.getAddress();
            if (!address.getAddressSpace().equals(start.getAddressSpace()) ||
                    address.compareTo(end) > 0) break;
            result.add(symbolRow(symbol));
        }
        // Include dynamic entry labels, which the iterator may omit.
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(start)) {
            Map<String, Object> row = symbolRow(symbol);
            if (!result.contains(row)) result.add(row);
        }
        return result;
    }

    private void writeJson(Path path, Object value) throws Exception {
        Files.writeString(path, gson.toJson(value) + "\n", StandardCharsets.UTF_8);
    }

    private void exportInstructions(AddressSet requested, Path output, String stem,
            Map<String, Object> target) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        AddressSet covered = new AddressSet();
        long pcodeCount = 0;
        boolean crossesEnd = false;
        try (BufferedWriter listing = Files.newBufferedWriter(
                    output.resolve(stem + ".listing.txt"), StandardCharsets.UTF_8);
                BufferedWriter pcode = Files.newBufferedWriter(
                    output.resolve(stem + ".pcode.txt"), StandardCharsets.UTF_8)) {
            listing.write("# Instruction starts in the explicitly requested extent only.\n");
            pcode.write("# Raw instruction p-code from getPcode(false); no high-level SSA transforms.\n");
            InstructionIterator instructions = currentProgram.getListing().getInstructions(requested, true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = instructions.next();
                Address address = instruction.getAddress();
                byte[] bytes = instruction.getBytes();
                String encoded = hexBytes(bytes);
                listing.write(address + "  " + encoded + "  " + instruction + "\n");
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", address.toString());
                row.put("size_bytes", instruction.getLength());
                row.put("bytes_hex", encoded);
                row.put("text", instruction.toString());
                row.put("flow_type", instruction.getFlowType().toString());
                List<String> flows = new ArrayList<>();
                for (Address flow : instruction.getFlows()) flows.add(flow.toString());
                row.put("flows", flows);
                Address fallthrough = instruction.getFallThrough();
                row.put("fallthrough", fallthrough == null ? null : fallthrough.toString());
                List<String> operations = new ArrayList<>();
                PcodeOp[] ops = instruction.getPcode(false);
                for (int i = 0; i < ops.length; i++) {
                    String text = ops[i].toString();
                    operations.add(text);
                    pcode.write(address + ":" + i + "  " + text + "\n");
                }
                row.put("raw_pcode", operations);
                rows.add(row);
                pcodeCount += ops.length;
                covered.add(instruction.getMinAddress(), instruction.getMaxAddress());
                if (!requested.contains(instruction.getMaxAddress())) crossesEnd = true;
            }
        }
        writeJson(output.resolve(stem + ".instructions.json"), rows);
        target.put("instruction_count", rows.size());
        target.put("raw_pcode_count", pcodeCount);
        target.put("listing_file", stem + ".listing.txt");
        target.put("instructions_file", stem + ".instructions.json");
        target.put("raw_pcode_file", stem + ".pcode.txt");
        target.put("instruction_scope", "Instruction starts within requested extent, independent of preserved function body");
        target.put("instruction_crosses_requested_end", crossesEnd);
        target.put("bytes_without_instructions", ranges(requested.subtract(covered)));
        target.put("instruction_export_truncated", false);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("Usage: SelectedExport.java SPECS_JSON OUTPUT_DIR TIMEOUT_SECONDS");
        }
        Path specsPath = Path.of(args[0]);
        Path output = Path.of(args[1]);
        int timeout = Integer.parseInt(args[2]);
        if (timeout < 1) throw new IllegalArgumentException("Timeout must be positive");
        JsonArray specs = JsonParser.parseString(Files.readString(specsPath)).getAsJsonArray();
        Files.createDirectories(output);
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("program", currentProgram.getName());
        report.put("executable_path", currentProgram.getExecutablePath());
        report.put("executable_sha256", currentProgram.getExecutableSHA256());
        report.put("language", currentProgram.getLanguageID().toString());
        report.put("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        report.put("image_base", currentProgram.getImageBase().toString());
        report.put("specs_path", specsPath.toAbsolutePath().toString());
        report.put("selected_only", true);
        report.put("scope_truncated", true);
        report.put("scope_note", "Only explicitly selected functions are exported; this is not whole-program analysis");
        report.put("automatic_analysis_requested_by_script", false);
        report.put("timeout_seconds_per_function", timeout);
        report.put("prototype_warning", "Prototypes are existing Ghidra/default inference; Rust/JVM ABIs and types are unverified. No register parameters or invented C type layouts are applied.");
        report.put("decompiler_flow_warning", "Instruction/p-code export is restricted to the requested extent. Decompiled C may follow beyond that extent when call/no-return metadata is unknown; function bodies alone are not a control-flow boundary. No flow or no-return overrides are invented.");
        List<Map<String, Object>> targets = new ArrayList<>();
        report.put("targets", targets);
        boolean cancelled = false;
        DecompInterface decompiler = new DecompInterface();
        try (BufferedWriter combined = Files.newBufferedWriter(
                output.resolve("decompiled.c"), StandardCharsets.UTF_8)) {
            combined.write("/* Selected Ghidra pseudocode. Prototypes/types are unverified inference. Review instruction bytes and raw p-code. */\n");
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Cannot open program in decompiler: " + decompiler.getLastMessage());
            }
            int index = 0;
            for (JsonElement specElement : specs) {
                monitor.checkCancelled();
                JsonObject spec = specElement.getAsJsonObject();
                Map<String, Object> row = new LinkedHashMap<>();
                targets.add(row);
                row.put("spec", gson.fromJson(spec, Map.class));
                String label = spec.has("label") ? spec.get("label").getAsString() : "target_" + index;
                row.put("label", label);
                String stem = String.format("%02d-", index++) + label.replaceAll("[^A-Za-z0-9_.-]", "_");
                try {
                    long size = spec.get("size").getAsLong();
                    if (size < 1 || size > MAX_TARGET_BYTES) {
                        throw new IllegalArgumentException("size must be 1.." + MAX_TARGET_BYTES + " bytes");
                    }
                    boolean relative = spec.has("image_offset_hex");
                    if (relative == spec.has("address_hex")) {
                        throw new IllegalArgumentException("Specify exactly one of image_offset_hex or address_hex");
                    }
                    Address start = relative
                        ? currentProgram.getImageBase().addNoWrap(parseUnsignedHex(spec.get("image_offset_hex").getAsString()))
                        : currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(parseUnsignedHex(spec.get("address_hex").getAsString()).longValue());
                    Address end = start.addNoWrap(size - 1);
                    AddressSet requested = new AddressSet(start, end);
                    row.put("requested_ranges", ranges(requested));
                    row.put("address", start.toString());
                    row.put("size_bytes", size);
                    if (!currentProgram.getMemory().contains(requested)) {
                        throw new IllegalArgumentException("Requested extent is not wholly mapped in program memory");
                    }
                    row.put("original_symbols", originalSymbols(start, end));
                    FunctionManager manager = currentProgram.getFunctionManager();
                    Function function = manager.getFunctionAt(start);
                    boolean overrideBody = spec.has("set_body_to_requested_extent") &&
                        spec.get("set_body_to_requested_extent").getAsBoolean();
                    row.put("set_body_to_requested_extent_requested", overrideBody);
                    row.put("original_body_ranges", function == null ? null : ranges(function.getBody()));
                    row.put("existing_body_mutated", false);
                    if (function == null) {
                        Function containing = manager.getFunctionContaining(start);
                        if (containing != null) {
                            row.put("overlapping_existing_function", containing.getName());
                            row.put("overlapping_existing_function_address", containing.getEntryPoint().toString());
                            throw new IllegalStateException("Selected entry lies inside an existing function; preserving its extent");
                        }
                    }
                    DisassembleCommand command = new DisassembleCommand(start, requested, true);
                    command.enableCodeAnalysis(false);
                    row.put("bounded_disassembly_ok", command.applyTo(currentProgram, monitor));
                    row.put("bounded_disassembly_message", command.getStatusMsg());
                    row.put("function_existed_at_entry", function != null);
                    if (function == null) {
                        String name = "selected_" + label.replaceAll("[^A-Za-z0-9_]", "_");
                        function = manager.createFunction(name, start, requested, SourceType.ANALYSIS);
                        row.put("function_created_for_export", true);
                        row.put("created_function_name_source", "Selected specification label, not a recovered source name");
                        if (function == null) throw new IllegalStateException("Cannot create function without overlapping an existing function");
                    } else {
                        row.put("function_created_for_export", false);
                        if (overrideBody) {
                            boolean changed = !function.getBody().hasSameAddresses(requested);
                            function.setBody(requested);
                            row.put("existing_body_mutated", changed);
                            row.put("body_override_reason", "Explicit selected specification opt-in; original body retained in original_body_ranges");
                        }
                    }
                    row.put("name", function.getName());
                    row.put("qualified_name", function.getName(true));
                    row.put("prototype", function.getPrototypeString(false, false));
                    row.put("signature_source", function.getSignatureSource().toString());
                    row.put("calling_convention", function.getCallingConventionName());
                    row.put("external", function.isExternal());
                    row.put("body_ranges", ranges(function.getBody()));
                    row.put("body_matches_requested_extent", function.getBody().hasSameAddresses(requested));
                    row.put("body_outside_requested_extent", ranges(function.getBody().subtract(requested)));
                    row.put("existing_function_body_preserved",
                        !Boolean.TRUE.equals(row.get("function_created_for_export")) &&
                        !Boolean.TRUE.equals(row.get("existing_body_mutated")));
                    exportInstructions(requested, output, stem, row);
                    long before = System.nanoTime();
                    DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
                    row.put("decompile_elapsed_ns", System.nanoTime() - before);
                    row.put("decompile_timed_out", result.isTimedOut());
                    row.put("decompile_cancelled", result.isCancelled());
                    row.put("decompile_failed_to_start", result.failedToStart());
                    row.put("decompile_error", result.getErrorMessage());
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        String c = result.getDecompiledFunction().getC();
                        row.put("status", "decompiled");
                        row.put("c", c);
                        row.put("c_file", stem + ".c");
                        Files.writeString(output.resolve(stem + ".c"), c, StandardCharsets.UTF_8);
                        combined.write("\n/* Selected label: " + label.replace("*/", "* /") + "; entry: " + start + " */\n" + c + "\n");
                    } else row.put("status", result.isTimedOut() ? "timed_out" : "decompile_failed");
                } catch (CancelledException exception) {
                    row.put("status", "cancelled");
                    cancelled = true;
                    break;
                } catch (Exception exception) {
                    row.put("status", "failed");
                    row.put("error", exception.getClass().getName() + ": " + exception.getMessage());
                }
                // Keep a reviewable checkpoint if a later native request fails.
                report.put("export_complete", false);
                report.put("analysis_timed_out", analysisTimeoutOccurred());
                writeJson(output.resolve("selected.json"), report);
            }
        } catch (CancelledException exception) {
            cancelled = true;
        } finally {
            decompiler.dispose();
            long succeeded = targets.stream().filter(row -> "decompiled".equals(row.get("status"))).count();
            report.put("requested_count", specs.size());
            report.put("attempted_count", targets.size());
            report.put("decompiled_count", succeeded);
            report.put("failed_count", targets.size() - succeeded);
            report.put("truncated", cancelled || targets.size() != specs.size());
            report.put("cancelled", cancelled);
            report.put("analysis_timed_out", analysisTimeoutOccurred());
            report.put("export_complete", !cancelled && targets.size() == specs.size());
            writeJson(output.resolve("selected.json"), report);
        }
        println("SELECTED_EXPORT_OK " + output.resolve("selected.json"));
    }
}
