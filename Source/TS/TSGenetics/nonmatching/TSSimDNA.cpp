#include "TSSimDNA.h"

namespace nTSGenetics
{
    // NON-MATCHING: 
    //  TARGET                                                   CURRENT (2025)                             
    //  0:    mflr    r0                                         0:    mflr    r0                           
    //  4:    stmw    r29,-0xc(r1)                               4:    stmw    r29,-0xc(r1)                 
    //  8:    mr      r29,r3                                     8:    mr      r29,r3                       
    //  c:    stw     r0,8(r1)                                   c:    stw     r0,8(r1)                     
    //  10:    stwu    r1,-0x50(r1)                              10:    stwu    r1,-0x50(r1)                
    //  14:    bl      func_010DA500                      i      14:    bl      __ZN11nTSGenetics10cITSSimDNAC2Ev
    //  18:    lis     r2,__ZTVN11nTSGenetics9cTSSimDNAE@hai      18:    lis     r2,__ZTVN11nTSGenetics9cTSSimDNAE+0x8@ha
    //  1c:    li      r0,0                                      1c:    li      r0,0                        
    //  20:    addi    r1,r1,0x50                                20:    addi    r1,r1,0x50                  
    //  24:    addi    r2,r2,__ZTVN11nTSGenetics9cTSSimDNAE@lr      24:    addi    r2,r2,__ZTVN11nTSGenetics9cTSSimDNAE+0x8@l
    //  28:    stw     r0,8(r29)                                 28:    stw     r0,8(r29)                   
    //  2c:    stw     r0,4(r29)                                 2c:    stw     r0,4(r29)                   
    //  30:    addi    r2,r2,8                            <                                                 
    //  34:    stw     r2,0(r29)                                 30:    stw     r2,0(r29)                   
    //  38:    lwz     r0,8(r1)                                  34:    lwz     r0,8(r1)                    
    //  3c:    lmw     r29,-0xc(r1)                              38:    lmw     r29,-0xc(r1)                
    //  40:    mtlr    r0                                        3c:    mtlr    r0                          
    //  44:    blr                                               40:    blr   
    //
    // also it duplicates the function for some reason
    cTSSimDNA::cTSSimDNA() {
        unk4 = 0;
        unk8 = 0;
    }
} // namespace nTSGenetics
