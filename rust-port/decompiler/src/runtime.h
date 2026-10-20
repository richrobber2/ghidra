/* SPDX-License-Identifier: Apache-2.0
 * Guarded machine-level C support. GNU C11, uint64_t six-integer SysV model.
 * Unknown values and unsupported memory/provenance never become invented data.
 */
#ifndef RUST_GHIDRA_MACHINE_C_RUNTIME
#define RUST_GHIDRA_MACHINE_C_RUNTIME
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

typedef struct { uint64_t x, k; unsigned p; } rg_value;
/* p=0 is scalar, p=1 is this invocation's stack, p=2 is invalid/partial
 * provenance, and p>=3 is image object p-2. Image x is an object-relative
 * offset, never an ELF address or a reconstructed host pointer. */
typedef struct { const unsigned char *bytes; uint64_t size; } rg_image_object;
enum { RG_CF=1, RG_PF=2, RG_ZF=4, RG_SF=8, RG_OF=16, RG_ALL=31 };
enum { RG_ADD,RG_ADC,RG_SUB,RG_SBB,RG_AND,RG_OR,RG_XOR,RG_IMUL,
       RG_SHL,RG_SHR,RG_SAR,RG_ROL,RG_ROR };
enum { RG_STACK_SIZE=8192 };
#define RG_STACK_BASE UINT64_C(0x100000)
#define RG_ENTRY_SP (RG_STACK_BASE + RG_STACK_SIZE/2 + 8)
/* The stack-protector canary (%fs:0x28) is an object of its own with no
 * bytes: it can be spilled and compared with itself, never read through or
 * returned. Image ids never reach it (at most image_count). */
#define RG_CANARY UINT_MAX
typedef struct {
    rg_value r[16];
    unsigned char mem[RG_STACK_SIZE], known[RG_STACK_SIZE];
    uint16_t provenance[RG_STACK_SIZE];
    unsigned pointer_origin[RG_STACK_SIZE];
    unsigned flags, known_flags;
    const rg_image_object *images;
    unsigned image_count;
} rg_state;

static _Noreturn void rg_fail(void) { abort(); }
static uint64_t rg_mask(unsigned w) {
    if(w!=8 && w!=16 && w!=32 && w!=64) rg_fail();
    return w==64 ? UINT64_MAX : (UINT64_C(1)<<w)-1;
}
static rg_value rg_const(uint64_t x) { return (rg_value){x,UINT64_MAX,0}; }
static rg_value rg_canary(void) { return (rg_value){0,UINT64_MAX,RG_CANARY}; }
static uint64_t rg_need(rg_value v, unsigned w) {
    uint64_t mask=rg_mask(w);
    if((v.k&mask)!=mask) rg_fail();
    return v.x&mask;
}
static uint64_t rg_num(rg_value v, unsigned w) {
    if(v.p) rg_fail();
    return rg_need(v,w);
}
static const rg_image_object *rg_image_object_for(rg_state *s,unsigned provenance) {
    if(provenance<3 || !s->images || provenance-3>=s->image_count) rg_fail();
    const rg_image_object *object=&s->images[provenance-3];
    if(!object->bytes) rg_fail();
    return object;
}
static rg_value rg_image(rg_state *s,unsigned id,uint64_t offset) {
    if(!id || id>UINT_MAX-2 || id>s->image_count) rg_fail();
    unsigned provenance=id+2;
    const rg_image_object *object=rg_image_object_for(s,provenance);
    if(offset>object->size) rg_fail();
    return (rg_value){offset,UINT64_MAX,provenance};
}
static const unsigned char *rg_pointer_result(rg_state *s,rg_value v) {
    uint64_t offset=rg_need(v,64);
    const rg_image_object *object=rg_image_object_for(s,v.p);
    if(offset>object->size || offset>SIZE_MAX) rg_fail();
    return object->bytes+(size_t)offset;
}
static rg_value rg_reg(rg_state *s,unsigned n,unsigned w,unsigned high) {
    unsigned shift=high?8:0;
    rg_value v=s->r[n];
    v.x=(v.x>>shift)&rg_mask(w); v.k=(v.k>>shift)&rg_mask(w);
    if(w!=64 && v.p) v.p=2;
    return v;
}
static void rg_setreg(rg_state *s,unsigned n,unsigned w,unsigned high,rg_value v) {
    if(w==64) { s->r[n]=v; return; }
    if(w==32) {
        s->r[n]=(rg_value){v.x&UINT32_MAX,(v.k&UINT32_MAX)|UINT64_C(0xffffffff00000000),v.p?2:0};
        return;
    }
    unsigned shift=high?8:0; uint64_t mask=rg_mask(w)<<shift;
    s->r[n].x=(s->r[n].x&~mask)|((v.x<<shift)&mask);
    s->r[n].k=(s->r[n].k&~mask)|((v.k<<shift)&mask);
    if(s->r[n].p || v.p) s->r[n].p=2;
}
static rg_value rg_lea_value(rg_state *s,rg_value a,int index,unsigned scale,uint64_t disp) {
    rg_value b=index<0?rg_const(0):s->r[index];
    if(a.p==2 || b.p==2 || (a.p && b.p) || (b.p && scale!=1)) rg_fail();
    return (rg_value){rg_need(a,64)+rg_need(b,64)*scale+disp,UINT64_MAX,a.p?a.p:b.p};
}
static rg_value rg_lea(rg_state *s,int base,int index,unsigned scale,uint64_t disp) {
    return rg_lea_value(s,base<0?rg_const(0):s->r[base],index,scale,disp);
}
/* An absolute ET_EXEC displacement plus a scaled index: the image object comes
   from the displacement, never from the index. */
static rg_value rg_lea_from(rg_state *s,rg_value image,int index,unsigned scale) {
    return rg_lea_value(s,image,index,scale,0);
}
static unsigned rg_slot(rg_value address,unsigned w) {
    (void)rg_mask(w);
    uint64_t a=rg_need(address,64), length=w/8;
    if(address.p!=1 || a<RG_STACK_BASE || a-RG_STACK_BASE>RG_STACK_SIZE-length) rg_fail();
    return (unsigned)(a-RG_STACK_BASE);
}
static rg_value rg_load(rg_state *s,rg_value address,unsigned w) {
    if(address.p>=3) {
        (void)rg_mask(w);
        uint64_t offset=rg_need(address,64), n=w/8;
        const rg_image_object *object=rg_image_object_for(s,address.p);
        if(offset>object->size || n>object->size-offset || offset>SIZE_MAX-n) rg_fail();
        uint64_t x=0;
        for(unsigned i=0;i<n;i++) x|=(uint64_t)object->bytes[(size_t)offset+i]<<(8*i);
        return (rg_value){x,rg_mask(w),0};
    }
    unsigned at=rg_slot(address,w), n=w/8, any=0, complete=(w==64);
    unsigned origin=s->pointer_origin[at];
    rg_value v={0,0,0};
    for(unsigned i=0;i<n;i++) {
        v.x|=(uint64_t)s->mem[at+i]<<(8*i);
        v.k|=(uint64_t)s->known[at+i]<<(8*i);
        any|=s->provenance[at+i]!=0;
        complete&=s->provenance[at+i]==at+1 && s->pointer_origin[at+i]==origin;
    }
    v.p=any?(complete && (origin==1 || origin>=3)?origin:2):0;
    return v;
}
static void rg_store(rg_state *s,rg_value address,unsigned w,rg_value v) {
    unsigned at=rg_slot(address,w), n=w/8;
    /* Caller state and the return-address slot are outside this leaf model. */
    if(address.x+n>RG_ENTRY_SP) rg_fail();
    uint16_t tag=v.p==0?0:((v.p==1 || v.p>=3) && w==64?(uint16_t)(at+1):UINT16_MAX);
    for(unsigned i=0;i<n;i++) {
        s->mem[at+i]=(unsigned char)(v.x>>(8*i));
        s->known[at+i]=(unsigned char)(v.k>>(8*i));
        s->provenance[at+i]=tag;
        s->pointer_origin[at+i]=v.p;
    }
}
static void rg_bit(rg_state *s,unsigned bit,unsigned value) {
    s->flags=(s->flags&~bit)|(value?bit:0); s->known_flags|=bit;
}
static void rg_szp(rg_state *s,uint64_t r,unsigned w) {
    unsigned x=(unsigned)(r&255); x^=x>>4; x^=x>>2; x^=x>>1;
    rg_bit(s,RG_ZF,r==0); rg_bit(s,RG_SF,(unsigned)(r>>(w-1))&1); rg_bit(s,RG_PF,(x&1)==0);
}
static __int128 rg_signed(uint64_t x,unsigned w) {
    x&=rg_mask(w);
    return (__int128)x-((x>>(w-1))?((__int128)1<<w):0);
}
static rg_value rg_extend(rg_value v,unsigned from,unsigned to,unsigned sign) {
    if(v.p) { v.p=2; return v; }
    uint64_t mask=rg_mask(from), target=rg_mask(to);
    v.x&=mask; v.k&=mask;
    if(!sign) v.k|=target&~mask;
    else if(v.k&(UINT64_C(1)<<(from-1))) {
        if(v.x&(UINT64_C(1)<<(from-1))) v.x|=target&~mask;
        v.k|=target&~mask;
    }
    return v;
}
static rg_value rg_alu(rg_state *s,unsigned op,rg_value av,rg_value bv,unsigned w) {
    unsigned shift=op>=RG_SHL && op<=RG_ROR;
    uint64_t mask=rg_mask(w), a=rg_need(av,w), b=rg_need(bv,shift?8:w), r=0;
    unsigned pointer=0;
    if(av.p || bv.p) {
        if(w!=64 || av.p==2 || bv.p==2) rg_fail();
        /* The canary minus, or XOR, itself is zero with an equal SUB's flags. */
        if(av.p==RG_CANARY && bv.p==RG_CANARY && a==b && (op==RG_SUB || op==RG_XOR)) {
            rg_szp(s,0,64); rg_bit(s,RG_CF,0); rg_bit(s,RG_OF,0);
            return rg_const(0);
        }
        if(op==RG_ADD && (!av.p || !bv.p)) { r=a+b; pointer=av.p?av.p:bv.p; }
        else if(op==RG_SUB && av.p && !bv.p) { r=a-b; pointer=av.p; }
        else if(op==RG_SUB && av.p && av.p==bv.p) { r=a-b; pointer=0; }
        else if(op==RG_AND && av.p==1 && !bv.p && (~b)<=15 && (((~b)&((~b)+1))==0)) { r=a&b; pointer=1; }
        else rg_fail();
        s->known_flags=0;
        return (rg_value){r,UINT64_MAX,pointer};
    }
    if(op==RG_SHL || op==RG_SHR || op==RG_SAR || op==RG_ROL || op==RG_ROR) {
        unsigned count=(unsigned)b&(w==64?63:31);
        if(op==RG_ROL || op==RG_ROR) {
            unsigned effective=count%w;
            if(effective) {
                r=op==RG_ROL?((a<<effective)|(a>>(w-effective))):((a>>effective)|(a<<(w-effective)));
                r&=mask;
            } else r=a;
            if(count) rg_bit(s,RG_CF,op==RG_ROL?(r&1):(r>>(w-1))&1);
            if(count==1) rg_bit(s,RG_OF,op==RG_ROL?((r>>(w-1))^(s->flags&RG_CF))&1:((r>>(w-1))^(r>>(w-2)))&1);
            else if(count) s->known_flags&=~RG_OF;
            return rg_const(r);
        }
        if(!count) return rg_const(a);
        if(op==RG_SHL) r=count>=w?0:(a<<count)&mask;
        else if(op==RG_SHR) r=count>=w?0:a>>count;
        else {
            unsigned sign=(unsigned)(a>>(w-1))&1;
            r=count>=w?(sign?mask:0):(a>>count)|(sign?(mask^(mask>>count)):0);
        }
        rg_szp(s,r,w);
        if(op==RG_SAR) rg_bit(s,RG_CF,(unsigned)(a>>(count>=w?w-1:count-1))&1);
        else if(count<w) rg_bit(s,RG_CF,(unsigned)(op==RG_SHL?a>>(w-count):a>>(count-1))&1);
        else s->known_flags&=~RG_CF;
        if(count==1) rg_bit(s,RG_OF,op==RG_SHL?((r>>(w-1))^(s->flags&RG_CF))&1:op==RG_SHR?(a>>(w-1))&1:0);
        else s->known_flags&=~RG_OF;
        return rg_const(r&mask);
    }
    if(op==RG_AND || op==RG_OR || op==RG_XOR) {
        r=(op==RG_AND?a&b:op==RG_OR?a|b:a^b)&mask;
        rg_szp(s,r,w); rg_bit(s,RG_CF,0); rg_bit(s,RG_OF,0);
    } else if(op==RG_IMUL) {
        __int128 p=rg_signed(a,w)*rg_signed(b,w), limit=(__int128)1<<(w-1);
        r=(uint64_t)((__uint128_t)a*b)&mask;
        s->known_flags&=~(RG_ZF|RG_SF|RG_PF);
        rg_bit(s,RG_CF,p < -limit || p >= limit); rg_bit(s,RG_OF,p < -limit || p >= limit);
    } else {
        unsigned carry=0;
        if(op==RG_ADC || op==RG_SBB) { if(!(s->known_flags&RG_CF)) rg_fail(); carry=(s->flags&RG_CF)!=0; }
        __int128 signed_result;
        if(op==RG_ADD || op==RG_ADC) {
            __uint128_t wide=(__uint128_t)a+b+carry;
            r=(uint64_t)wide&mask; rg_bit(s,RG_CF,(unsigned)(wide>>w)&1);
            signed_result=rg_signed(a,w)+rg_signed(b,w)+carry;
        } else if(op==RG_SUB || op==RG_SBB) {
            r=(a-b-carry)&mask; rg_bit(s,RG_CF,(__uint128_t)a < (__uint128_t)b+carry);
            signed_result=rg_signed(a,w)-rg_signed(b,w)-carry;
        } else { rg_fail(); signed_result=0; }
        __int128 limit=(__int128)1<<(w-1);
        rg_bit(s,RG_OF,signed_result < -limit || signed_result >= limit); rg_szp(s,r,w);
    }
    return rg_const(r);
}
/* Same-object pointer equality is independent of the unknown image load base.
 * Keep every other CMP flag unknown: subtraction alone does not establish the
 * address-dependent flags of the original machine pointers. */
static void rg_compare(rg_state *s,rg_value a,rg_value b,unsigned w) {
    if(w==64 && a.p==RG_CANARY && b.p==RG_CANARY) { (void)rg_alu(s,RG_SUB,a,b,w); return; }
    if(w==64 && a.p>=3 && a.p==b.p) {
        (void)rg_image_object_for(s,a.p);
        uint64_t x=rg_need(a,64), y=rg_need(b,64);
        s->known_flags=0;
        rg_bit(s,RG_ZF,x==y);
        return;
    }
    (void)rg_alu(s,RG_SUB,a,b,w);
}
static rg_value rg_unary(rg_state *s,unsigned op,rg_value v,unsigned w) {
    if(op==3) { if(v.p) rg_fail(); v.x=(~v.x)&rg_mask(w); return v; }
    unsigned cf=s->flags&RG_CF, ck=s->known_flags&RG_CF;
    rg_value result=op==2?rg_alu(s,RG_SUB,rg_const(0),v,w):rg_alu(s,op==0?RG_ADD:RG_SUB,v,rg_const(1),w);
    if(op!=2) { s->flags=(s->flags&~RG_CF)|cf; s->known_flags=(s->known_flags&~RG_CF)|ck; }
    return result;
}
static unsigned rg_condition(rg_state *s,unsigned condition) {
    unsigned need=0;
    if(condition<2) need=RG_OF;
    else if(condition<4) need=RG_CF;
    else if(condition<6) need=RG_ZF;
    else if(condition<8) need=RG_CF|RG_ZF;
    else if(condition<10) need=RG_SF;
    else if(condition<12) need=RG_PF;
    else if(condition<14) need=RG_SF|RG_OF;
    else need=RG_ZF|RG_SF|RG_OF;
    if((s->known_flags&need)!=need) rg_fail();
    unsigned cf=(s->flags&RG_CF)!=0,pf=(s->flags&RG_PF)!=0,zf=(s->flags&RG_ZF)!=0;
    unsigned sf=(s->flags&RG_SF)!=0,of=(s->flags&RG_OF)!=0;
    switch(condition) {
        case 0:return of; case 1:return !of; case 2:return cf; case 3:return !cf;
        case 4:return zf; case 5:return !zf; case 6:return cf||zf; case 7:return !cf&&!zf;
        case 8:return sf; case 9:return !sf; case 10:return pf; case 11:return !pf;
        case 12:return sf!=of; case 13:return sf==of; case 14:return zf||(sf!=of);
        case 15:return !zf&&(sf==of); default:rg_fail(); return 0;
    }
}
#endif
