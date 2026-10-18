/* SPDX-License-Identifier: Apache-2.0
 * Direct behavioral/provenance gate for the generated-C support boundary.
 * Only trusted helper calls execute here; rejected machine code is not run.
 */
#include "runtime.h"
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

/* The explicit gap prevents one object's one-past address from also being the
 * other object's first byte. No comparison of unrelated pointer ordering or
 * subtraction is used by this harness. */
static const struct {
    unsigned char first[32], gap[64], second[24];
} fixture_bytes = {
    {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
     0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
     0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
     0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f},
    {0},
    {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
     0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
     0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7}
};
static const rg_image_object objects[] = {
    {fixture_bytes.first,sizeof fixture_bytes.first},
    {fixture_bytes.second,sizeof fixture_bytes.second}
};

static int emit_number(uint64_t value) {
    printf("{\"value\":%llu}\n",(unsigned long long)value);
    return 0;
}
static int emit_pointer(const unsigned char *pointer) {
    for(unsigned object=0;object<sizeof objects/sizeof objects[0];object++) {
        for(uint64_t offset=0;offset<=objects[object].size;offset++) {
            if(pointer==objects[object].bytes+(size_t)offset) {
                int byte=offset==objects[object].size?-1:objects[object].bytes[offset];
                printf("{\"object\":%u,\"offset\":%llu,\"byte\":%d}\n",
                    object+1,(unsigned long long)offset,byte);
                return 0;
            }
        }
    }
    puts("{\"object\":0,\"offset\":0,\"byte\":-1}");
    return 0;
}
static int limit_resources(void) {
    struct rlimit core={0,0},cpu={2,2},memory={256U<<20,256U<<20},file={1U<<20,1U<<20};
    return setrlimit(RLIMIT_CORE,&core) || setrlimit(RLIMIT_CPU,&cpu) ||
        setrlimit(RLIMIT_AS,&memory) || setrlimit(RLIMIT_FSIZE,&file);
}

int main(int argc,char **argv) {
    if(argc!=2 || limit_resources()) return 2;
    const char *name=argv[1];
    rg_state s={0};
    s.images=objects;
    s.image_count=sizeof objects/sizeof objects[0];
    rg_value slot={RG_ENTRY_SP-32,UINT64_MAX,1};

    if(!strcmp(name,"load_widths")) {
        rg_value address=rg_image(&s,1,3);
        printf("{\"values\":[%llu,%llu,%llu,%llu]}\n",
            (unsigned long long)rg_num(rg_load(&s,address,8),8),
            (unsigned long long)rg_num(rg_load(&s,address,16),16),
            (unsigned long long)rg_num(rg_load(&s,address,32),32),
            (unsigned long long)rg_num(rg_load(&s,address,64),64));
        return 0;
    }
    if(!strcmp(name,"last_word"))
        return emit_number(rg_num(rg_load(&s,rg_image(&s,2,16),64),64));
    if(!strcmp(name,"pointer_offset"))
        return emit_pointer(rg_pointer_result(&s,rg_image(&s,2,5)));
    if(!strcmp(name,"pointer_one_past"))
        return emit_pointer(rg_pointer_result(&s,rg_image(&s,1,32)));
    if(!strcmp(name,"same_object_subtract")) {
        s.known_flags=RG_ALL;
        rg_value result=rg_alu(&s,RG_SUB,rg_image(&s,1,21),rg_image(&s,1,4),64);
        printf("{\"value\":%llu,\"known_flags\":%u}\n",
            (unsigned long long)rg_num(result,64),s.known_flags);
        return 0;
    }
    if(!strcmp(name,"same_object_compare_equal") || !strcmp(name,"same_object_compare_unequal")) {
        unsigned equal=!strcmp(name,"same_object_compare_equal");
        s.known_flags=RG_ALL;
        rg_compare(&s,rg_image(&s,1,7),rg_image(&s,1,equal?7:8),64);
        printf("{\"zf\":%u,\"not_zf\":%u,\"known_flags\":%u}\n",
            rg_condition(&s,4),rg_condition(&s,5),s.known_flags);
        return 0;
    }
    if(!strcmp(name,"scalar_plus_pointer"))
        return emit_pointer(rg_pointer_result(&s,rg_alu(&s,RG_ADD,rg_const(3),rg_image(&s,2,5),64)));
    if(!strcmp(name,"pointer_minus_scalar"))
        return emit_pointer(rg_pointer_result(&s,rg_alu(&s,RG_SUB,rg_image(&s,2,8),rg_const(3),64)));
    if(!strcmp(name,"lea_index")) {
        s.r[0]=rg_image(&s,1,4); s.r[1]=rg_const(3);
        return emit_pointer(rg_pointer_result(&s,rg_lea(&s,0,1,4,UINT64_MAX)));
    }
    if(!strcmp(name,"full_spill")) {
        rg_store(&s,slot,64,rg_image(&s,2,7));
        return emit_pointer(rg_pointer_result(&s,rg_load(&s,slot,64)));
    }
    if(!strcmp(name,"replace_spill_origin")) {
        rg_store(&s,slot,64,rg_image(&s,1,9));
        rg_store(&s,slot,64,rg_image(&s,2,11));
        return emit_pointer(rg_pointer_result(&s,rg_load(&s,slot,64)));
    }
    if(!strcmp(name,"unaligned_spill")) {
        slot.x=RG_ENTRY_SP-29;
        rg_store(&s,slot,64,rg_image(&s,1,3));
        return emit_pointer(rg_pointer_result(&s,rg_load(&s,slot,64)));
    }
    if(!strcmp(name,"scalar_replaces_spill")) {
        rg_store(&s,slot,64,rg_image(&s,2,7));
        rg_store(&s,slot,64,rg_const(UINT64_C(0x1122334455667788)));
        return emit_number(rg_num(rg_load(&s,slot,64),64));
    }
    if(!strcmp(name,"stack_spill")) {
        rg_value local={RG_ENTRY_SP-48,UINT64_MAX,1};
        rg_store(&s,local,8,rg_const(0x6a));
        rg_store(&s,slot,64,local);
        return emit_number(rg_num(rg_load(&s,rg_load(&s,slot,64),8),8));
    }

    if(!strcmp(name,"cross_object_subtract"))
        (void)rg_alu(&s,RG_SUB,rg_image(&s,1,7),rg_image(&s,2,7),64);
    else if(!strcmp(name,"cross_object_compare"))
        rg_compare(&s,rg_image(&s,1,7),rg_image(&s,2,7),64);
    else if(!strcmp(name,"pointer_compare_cf") || !strcmp(name,"pointer_compare_of") ||
            !strcmp(name,"pointer_compare_sf") || !strcmp(name,"pointer_compare_pf")) {
        unsigned condition=!strcmp(name,"pointer_compare_cf")?2:
            !strcmp(name,"pointer_compare_of")?0:!strcmp(name,"pointer_compare_sf")?8:10;
        s.known_flags=RG_ALL;
        rg_compare(&s,rg_image(&s,1,7),rg_image(&s,1,8),64);
        (void)rg_condition(&s,condition);
    }
    else if(!strcmp(name,"image_bitwise"))
        (void)rg_alu(&s,RG_AND,rg_image(&s,1,7),rg_const(UINT64_MAX),64);
    else if(!strcmp(name,"numeric_reification"))
        (void)rg_num(rg_image(&s,1,7),64);
    else if(!strcmp(name,"stack_pointer_result"))
        (void)rg_pointer_result(&s,slot);
    else if(!strcmp(name,"scalar_pointer_result"))
        (void)rg_pointer_result(&s,rg_const(7));
    else if(!strcmp(name,"invalid_pointer_result"))
        (void)rg_pointer_result(&s,(rg_value){7,UINT64_MAX,2});
    else if(!strcmp(name,"unknown_pointer_result")) {
        rg_value value=rg_image(&s,1,7); value.k&=~UINT64_C(1);
        (void)rg_pointer_result(&s,value);
    }
    else if(!strcmp(name,"past_pointer_result")) {
        rg_value value=rg_alu(&s,RG_ADD,rg_image(&s,1,32),rg_const(1),64);
        (void)rg_pointer_result(&s,value);
    }
    else if(!strcmp(name,"one_past_read"))
        (void)rg_load(&s,rg_image(&s,1,32),8);
    else if(!strcmp(name,"cross_end_read"))
        (void)rg_load(&s,rg_image(&s,2,17),64);
    else if(!strcmp(name,"far_read")) {
        rg_value address=rg_alu(&s,RG_ADD,rg_image(&s,1,0),rg_const(UINT64_MAX),64);
        (void)rg_load(&s,address,8);
    }
    else if(!strcmp(name,"image_write"))
        rg_store(&s,rg_image(&s,1,0),8,rg_const(1));
    else if(!strcmp(name,"partial_spill")) {
        rg_store(&s,slot,32,rg_image(&s,1,7));
        (void)rg_pointer_result(&s,rg_load(&s,slot,64));
    }
    else if(!strcmp(name,"split_origins")) {
        rg_store(&s,slot,32,rg_image(&s,1,7));
        slot.x+=4; rg_store(&s,slot,32,rg_image(&s,2,7));
        slot.x-=4; (void)rg_pointer_result(&s,rg_load(&s,slot,64));
    }
    else if(!strcmp(name,"overlapping_stores")) {
        rg_store(&s,slot,64,rg_image(&s,1,7));
        slot.x+=4; rg_store(&s,slot,64,rg_image(&s,2,7));
        slot.x-=4; (void)rg_pointer_result(&s,rg_load(&s,slot,64));
    }
    else if(!strcmp(name,"partial_scalar_overwrite")) {
        rg_store(&s,slot,64,rg_image(&s,1,7));
        slot.x+=2; rg_store(&s,slot,8,rg_const(0));
        slot.x-=2; (void)rg_pointer_result(&s,rg_load(&s,slot,64));
    }
    else if(!strcmp(name,"truncated_register")) {
        rg_setreg(&s,0,32,0,rg_image(&s,1,7));
        (void)rg_pointer_result(&s,rg_reg(&s,0,64,0));
    }
    else if(!strcmp(name,"pointer_flags")) {
        s.known_flags=RG_ALL;
        (void)rg_alu(&s,RG_ADD,rg_image(&s,1,7),rg_const(1),64);
        (void)rg_condition(&s,4);
    }
    else if(!strcmp(name,"scaled_pointer_index")) {
        s.r[0]=rg_image(&s,1,7);
        (void)rg_lea(&s,-1,0,2,0);
    }
    else if(!strcmp(name,"two_pointer_lea")) {
        s.r[0]=rg_image(&s,1,7); s.r[1]=rg_image(&s,2,7);
        (void)rg_lea(&s,0,1,1,0);
    }
    else if(!strcmp(name,"pointer_narrow_alu"))
        (void)rg_alu(&s,RG_ADD,rg_image(&s,1,7),rg_const(1),32);
    else if(!strcmp(name,"invalid_object_zero"))
        (void)rg_image(&s,0,0);
    else if(!strcmp(name,"invalid_object_high"))
        (void)rg_image(&s,3,0);
    else if(!strcmp(name,"absent_object_table")) {
        s.images=NULL; (void)rg_image(&s,1,0);
    }
    else return 2;
    /* A guard that returns normally is always a failed safety expectation. */
    puts("{\"unexpected_normal_return\":true}");
    return 0;
}
