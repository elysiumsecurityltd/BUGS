//---------------------------------------------------------------------------
#ifndef func_bcryptH
#define func_bcryptH
//---------------------------------------------------------------------------
#include <Classes.hpp>
//#include "libcrypt.h"
//---------------------------------------------------------------------------
class tbcrypt : public TThread
{
private:
protected:
        void __fastcall Execute();
        void __fastcall Test();
public:
        __fastcall tbcrypt(void);
};

//---------------------------------------------------------------------------
#endif
