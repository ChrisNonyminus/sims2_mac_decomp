// NON-MATCHING

// diff:
// TARGET                                                   CURRENT (1713)                             
// 0:    mflr    r0                                         0:    mflr    r0                           
// 4:    stmw    r29,-0xc(r1)                        r      4:    stmw    r30,-8(r1)                   
// 8:    mr.     r29,r4                              r      8:    mr.     r31,r4                       
// c:    stw     r0,8(r1)                                   c:    stw     r0,8(r1)                     
// 10:    stwu    r1,-0x50(r1)                              10:    stwu    r1,-0x50(r1)                
// 14:    beq     70 ~>                              i      14:    beq     7c ~>                       
// 18:    bl      __ZN2TS7GlobalsEv                         18:    bl      __ZN2TS7GlobalsEv           
// 1c:    lwz     r2,0(r3)                                  1c:    lwz     r2,0(r3)                    
// 20:    lwz     r0,0x18(r2)                        i      20:    lwz     r0,0(r2)                    
// 24:    mtctr   r0                                        24:    mtctr   r0                          
// 28:    mr      r12,r0                                    28:    mr      r12,r0                      
// 2c:    bctrl                                             2c:    bctrl                               
// 30:    mr.     r31,r3                             r      30:    mr.     r30,r3                      
// 34:    beq     70 ~>                              i      34:    beq     7c ~>                       
// 38:    lwz     r2,0(r29)                          r      38:    lwz     r2,0(r31)                   
// 3c:    lwz     r9,0(r31)                          <                                                 
// 40:    mr      r3,r29                             r      3c:    mr      r3,r31                      
// 44:    lwz     r0,0x48(r2)                        <                                                 
// 48:    lwz     r29,0xf8(r9)                       r      40:    lwz     r0,0(r2)                    
// 4c:    mtctr   r0                                        44:    mtctr   r0                          
// 50:    mr      r12,r0                                    48:    mr      r12,r0                      
// 54:    bctrl                                             4c:    bctrl                               
//                                                   >      50:    lwz     r2,0(r30)                   
// 58:    mtctr   r29                                |      54:    addi    r1,r1,0x50                  
// 5c:    mr      r12,r29                            r      58:    mr      r4,r3                       
// 60:    mr      r4,r3                              r      5c:    mr      r3,r30                      
//                                                   >      60:    lmw     r30,-8(r1)                  
//                                                   >      64:    lwz     r0,0(r2)                    
//                                                   >      68:    mtctr   r0                          
// 64:    mr      r3,r31                             r      6c:    mr      r12,r0                      
// 68:    bctrl                                      |      70:    lwz     r0,8(r1)                    
// 6c:    b       74 ~>                              |      74:    mtlr    r0                          
// 70: ~> li      r3,0                               |      78:    bctr                                
// 74: ~> addi    r1,r1,0x50                                7c: ~> addi    r1,r1,0x50                  
//                                                   >      80:    li      r3,0                        
// 78:    lwz     r0,8(r1)                                  84:    lwz     r0,8(r1)                    
// 7c:    lmw     r29,-0xc(r1)                       r      88:    lmw     r30,-8(r1)                  
// 80:    mtlr    r0                                        8c:    mtlr    r0                          
// 84:    blr                                               90:    blr                                 
// 88:    lis     r12,__ZN2TS7GlobalsEv@ha           <                                                 
// 8c:    ori     r12,r12,__ZN2TS7GlobalsEv@l        <                                                 
// 90:    mtctr   r12                                <                                                 
// 94:    bctr                                       <                                                 

#include "TSStateController.h"
#include "TSGlobals.h"
#include "TSNeighborhood.h"

uint32_t cTSGameStateController::RemoveNeighborhoodLot(cITSLotInfo const* lot) {
    cITSNeighborhood* nhood;
    uint32_t result = 0;
    uint32_t lot_id;
    if (lot != 0) {
        nhood = TS::Globals()->GetNeighborhood();
        if (nhood != 0) {
            lot_id = lot->LotGroupName();
            result = nhood->RemoveLot(lot_id);
        }
    }
    return result;
}