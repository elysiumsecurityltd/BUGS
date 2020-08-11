//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "func_bcrypt.h"
#include "bcrypt.h"
#include "libcrypt.h"

//---------------------------------------------------------------------------
//   Important: Methods and properties of objects in VCL can only be
//   used in a method called using Synchronize, for example:
//
//      Synchronize(UpdateCaption);
//
//   where UpdateCaption could look like:
//
//      void __fastcall bcrypt::UpdateCaption()
//      {
//        Form1->Caption = "Updated in a thread";
//      }
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------

   //---------------------------------------------------------------------------

__declspec(dllimport) int _binit(int,int,int,globalvar *);


__fastcall tbcrypt::tbcrypt() : TThread(True)
{
//  Priority = tpNormal;
  FreeOnTerminate = True;
//tpIdle	The thread executes only when the system is idle. Windows won't interrupt other threads to execute a thread with tpIdle priority.
//tpLowest	The thread's priority is two points below normal.
//tpLower	The thread's priority is one point below normal.
//tpNormal	The thread has normal priority.
//tpHigher	The thread's priority is one point above normal.
//tpHighest	The thread's priority is two points above normal.
//tpTimeCritical	The thread gets highest priority.
}
//---------------------------------------------------------------------------

void __fastcall tbcrypt::Test()
{
// Form_Main->ListBox1->Items->Add("test");
}
void __fastcall tbcrypt::Execute()
{
        //---- Place thread code here ----
         int power, bc, bs, mode, method, complexity, action, keylength, random,
      keytype, i;
  char buf[200]="";
  unsigned char *password;
  int rename = 0;





//HINSTANCE hlib = NULL;
//typedef int (CALLBACK *test_pbinit)(int,int,int,globalvar *);
//test_pbinit pbinit;
//I_BINIT         pbinit;
//I_BFILE        pbfile;

globalvar *varinit;

varinit = (globalvar *) malloc(sizeof(globalvar));

_binit(128,0,1,varinit);
//HANDLE hThreads;
//unsigned int threadId;

//hThreads = (HANDLE)_beginthreadex(
 //        NULL,          /* Thread security */

  //       0,         /* Thread stack size */
  //       threadMain,   /* Thread starting address */
  //       (void *)0,    /* Thread start argument */
  //       CREATE_SUSPENDED,  /* Create in suspended state */
  //       &threadId);   /* Thread ID */

//ResumeThread(hThreads);




//hlib= LoadLibrary("bcrypt.dll");

//pbinit = static_cast < test_pbinit> ( GetProcAddress (hlib,"_binit"));

//pbinit(keylength, random, 1,varinit);
//FreeLibrary(hlib);
//return 1;

//pbfile = (I_BFILE) GetProcAddress (hlib,"_bfile");

Form_Main->ListBox1->Clear();

bc = atoi(Form_Main->Edit_Bc->Text.c_str());
bs = atoi(Form_Main->Edit_Bs->Text.c_str());
complexity = atoi(Form_Main->Edit_Complexity->Text.c_str());
keylength = atoi(Form_Main->Label_Keylength->Caption.c_str());

if (strcmp(Form_Main->Combo_Mode->Text.c_str(),"Quiet") == 0)
        mode = 0;
   else
        {
        if (strcmp(Form_Main->Combo_Mode->Text.c_str(),"Verbose") == 0)
                mode = 1;
        else
                mode = 2;
        }


if (NULL != strstr(Form_Main->Combo_Power->Text.c_str(), "0"))
        power = 0;
else
        if (NULL != strstr(Form_Main->Combo_Power->Text.c_str(), "1"))
            power = 1;
        else
                if (NULL != strstr(Form_Main->Combo_Power->Text.c_str(), "2"))
                   power = 2;
                else
                        if (NULL != strstr(Form_Main->Combo_Power->Text.c_str(), "3"))
                            power = 3;
                        else
                            power = 4;


if (strcmp(Form_Main->Combo_Method->Text.c_str(),"Memory") == 0)
        method = 1;
   else
        method = 0;

        action = 0;

if (strcmp(Form_Main->Combo_Random->Text.c_str(),"ISAAC") == 0)
        random = 1;
   else
        random = 0;

if (strcmp(Form_Main->Combo_Keytype->Text.c_str(),"Password") == 0)
        keytype = 0;
   else
        keytype = 1;

char* source = StrNew(Form_Main->Edit_Crypt_Source->Text.c_str());
char* dest = StrNew(Form_Main->Edit_Crypt_Dest->Text.c_str());
char* keyfile = StrNew(Form_Main->Edit_Crypt_Keyfile->Text.c_str());

//Application->MessageBox("toto", "StrNew, StrDispose Example", MB_OK);
  // Deallocate memory.
//  StrDispose(psz);


if (strcmp(Form_Main->Edit_Crypt_Source->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a SOURCE FILE.");
//   FreeLibrary(hlib);
   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
   return;
   }

if (strcmp(Form_Main->Edit_Crypt_Dest->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a DESTINATION FILE.");
//   FreeLibrary(hlib);
   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
   return;
   }

if ((1 == keytype) && (strcmp(Form_Main->Edit_Crypt_Keyfile->Text.c_str(),"") == 0))
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a KEY FILE.");
//   FreeLibrary(hlib);
   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
   return;
   }

if (0 == keytype)
       Form_Main->ListBox1->Items->Add("Using Password");
   else
      {
        strcpy(buf,"Using Keyfile = ");
        strcat(buf,keyfile);
        Form_Main->ListBox1->Items->Add(buf);
      }
if (0 == action)
      Form_Main-> ListBox1->Items->Add("Crypting in Progress...");
   else
       Form_Main->ListBox1->Items->Add("DECrypting in Progress...");

if (FileExists("bcrypt.log"))
      DeleteFile("bcrypt.log");

if (
   (1 == keytype) || ((strcmp(Form_Main->Edit_Crypt_Password->Text.c_str(),"") != 0) &&
   (strcmp(Form_Main->Edit_Crypt_Password->Text.c_str(), Form_Main->Edit_Crypt_Verif->Text.c_str()) == 0))
   )

   {

    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Working...");
    Form_Main->ListBox1->Items->Add("");
    if (strcmp(Form_Main->Edit_Crypt_Source->Text.c_str(),Form_Main->Edit_Crypt_Dest->Text.c_str()) == 0)
       {
        strcat(source, ".BUG");
        Form_Main->ListBox1->Items->Add("Source and Destination filename are the same.");
        Form_Main->ListBox1->Items->Add("Renaming Source to:");
        Form_Main->ListBox1->Items->Add(source);
        rename = 1;
        if (FileExists(source))
         {
          Form_Main->ListBox1->Items->Add("ERROR.");
          Form_Main->ListBox1->Items->Add("Can't rename. Filename already exists");
  //        FreeLibrary(hlib);
          Form_Main->Button_Crypt_Action->Enabled = TRUE;
          Form_Main->Button_Decrypt_Action->Enabled = TRUE;
          Form_Main->Button_Hide_Action->Enabled = TRUE;
          Form_Main->Button_Keyfile_Action->Enabled = TRUE;
          Form_Main->Button_Crypt_Stop->Enabled = FALSE;
          return;
         }
        RenameFile(Form_Main->Edit_Crypt_Source->Text.c_str(), source);
        Form_Main->ListBox1->Items->Add("Done. Please Wait...");
       }
    else
       {
       if (FileExists(Form_Main->Edit_Crypt_Dest->Text.c_str()))
         {
          Form_Main->ListBox1->Items->Add("ERROR.");
          Form_Main->ListBox1->Items->Add("Destination File already exists");
        //  FreeLibrary(hlib);
          Form_Main->Button_Crypt_Action->Enabled = TRUE;
          Form_Main->Button_Decrypt_Action->Enabled = TRUE;
          Form_Main->Button_Hide_Action->Enabled = TRUE;
          Form_Main->Button_Keyfile_Action->Enabled = TRUE;
          Form_Main->Button_Crypt_Stop->Enabled = FALSE;
          return;
         }
       }


    Form_Main->ListBox1->Refresh();
    Form_Main->Timer1->Enabled = TRUE;

//    (*pbinit) (keylength, random, 1,varinit);

    password = (unsigned char *)malloc(varinit->NB_CHAR);

    if (Form_Main->Edit_Crypt_Password->Text.Length() > varinit->NB_CHAR)
      {
        i = varinit->NB_CHAR;
        Form_Main->ListBox1->Items->Add("Password length reduced.");
      }
    else
        i = Form_Main->Edit_Crypt_Password->Text.Length();

    strncpy(password, Form_Main->Edit_Crypt_Password->Text.c_str(), i);

 //   if ((*pbfile) (action,source,dest, Form_Main->Edit_Crypt_Keyfile->Text.c_str(),password, i,
//          power, complexity, bc, bs, method, mode, varinit) == 0)

if (1 == 1)
    {
            Form_Main->Timer1->Enabled = FALSE;
            Form_Main->ListBox1->Items->Add("");
            Form_Main->ListBox1->Items->Add("ERROR.");
            Form_Main->ListBox1->Items->Add("Please Look at the ADVANCED LOGS for more information");
    }
    else
    {
        if (1 == rename)
            {
            Form_Main->ListBox1->Items->Add("Deleting tempory file:");
            Form_Main->ListBox1->Items->Add(source);
            DeleteFile(source);
            }
        Form_Main->Edit_Crypt_Password->Clear();
        Form_Main->Edit_Crypt_Verif->Clear();
        Form_Main->Timer1->Enabled = FALSE;
        Form_Main->ListBox1->Items->Add("");
        Form_Main->ListBox1->Items->Add("Time To Complete: ");
        Form_Main->ListBox1->Items->Add(Form_Main->Label_Logs_Time->Caption);
        Form_Main->ListBox1->Items->Add("Done !");
        Form_Main->ListBox1->Items->Add("");
    }
 }
  else
    {
      Form_Main->ListBox1->Items->Add("ERROR.");
      Form_Main->ListBox1->Items->Add("Password Misspelled.");
 //     FreeLibrary(hlib);
      Form_Main->Timer1->Enabled = FALSE;
      Form_Main->Button_Crypt_Action->Enabled = TRUE;
      Form_Main->Button_Decrypt_Action->Enabled = TRUE;
      Form_Main->Button_Hide_Action->Enabled = TRUE;
      Form_Main->Button_Keyfile_Action->Enabled = TRUE;
      Form_Main->Button_Crypt_Stop->Enabled = FALSE;
      return;
    }

 //  FreeLibrary(hlib);
   free(password);
   Form_Main->RichEdit1->Lines->LoadFromFile("bcrypt.log");

   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
 return;
}

//---------------------------------------------------------------------------
