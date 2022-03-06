#include <stdint.h>

// nTSGenetics::cTSSimDNA::cTSSimDNA()

//  .global __ZN11nTSGenetics9cTSSimDNAC2Ev
//  __ZN11nTSGenetics9cTSSimDNAC2Ev:
//  /* 010CFCEC 010CECEC  7C 08 02 A6 */	mflr r0
//  /* 010CFCF0 010CECF0  BF A1 FF F4 */	stmw r29, -0xc(r1)
//  /* 010CFCF4 010CECF4  7C 7D 1B 78 */	mr r29, r3
//  /* 010CFCF8 010CECF8  90 01 00 08 */	stw r0, 8(r1)
//  /* 010CFCFC 010CECFC  94 21 FF B0 */	stwu r1, -0x50(r1)
//  /* 010CFD00 010CED00  48 00 A8 01 */	bl func_010DA500
//  /* 010CFD04 010CED04  3C 40 02 B0 */	lis r2, __ZTVN11nTSGenetics9cTSSimDNAE@ha
//  /* 010CFD08 010CED08  38 00 00 00 */	li r0, 0
//  /* 010CFD0C 010CED0C  38 21 00 50 */	addi r1, r1, 0x50
//  /* 010CFD10 010CED10  38 42 56 D0 */	addi r2, r2, __ZTVN11nTSGenetics9cTSSimDNAE@l
//  /* 010CFD14 010CED14  90 1D 00 08 */	stw r0, 8(r29)
//  /* 010CFD18 010CED18  90 1D 00 04 */	stw r0, 4(r29)
//  /* 010CFD1C 010CED1C  38 42 00 08 */	addi r2, r2, 8
//  /* 010CFD20 010CED20  90 5D 00 00 */	stw r2, 0(r29)
//  /* 010CFD24 010CED24  80 01 00 08 */	lwz r0, 8(r1)
//  /* 010CFD28 010CED28  BB A1 FF F4 */	lmw r29, -0xc(r1)
//  /* 010CFD2C 010CED2C  7C 08 03 A6 */	mtlr r0
//  /* 010CFD30 010CED30  4E 80 00 20 */	blr 
//  /* 010CFD34 010CED34  3D 80 01 0D */	lis r12, func_010DA500@h
//  /* 010CFD38 010CED38  61 8C A5 00 */	ori r12, r12, func_010DA500@l
//  /* 010CFD3C 010CED3C  7D 89 03 A6 */	mtctr r12
//  /* 010CFD40 010CED40  4E 80 04 20 */	bctr

namespace TSGenetics {
    class ITSSimDNA {
    public:
        ITSSimDNA();
        ~ITSSimDNA();
        virtual uint32_t QueryInterface(uint32_t, void**);
    };
    class TSSimDNA : public ITSSimDNA {
    public:
        TSSimDNA();
        ~TSSimDNA();
    private:
        uint32_t unk4;
        uint32_t unk8;
    };
}