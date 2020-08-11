//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop
#include <stdlib.h>

#include "include/bstandard.h"
#include "include/wrapper.h"
#include "include/utils.h"
#include "include/misc.h"
#include <math.h>

#include <alloc.h>
#include <dir.h>
#include <Filectrl.hpp>
#include <Registry.hpp>

#include "bcrypt.h"

//---------------------------------------------------------------------------

#pragma resource "*.dfm"

TForm_Main *Form_Main;
 int NB_BYTE;

globalvar *varinit;
char PATH_MAIN[MAXPATH];
char PATH_LOGS[MAXPATH];
char PATH_DOC[MAXPATH];
char *VERSION="Bcrypt Version: 4.1";

//int THREAD_START;
HANDLE T1;
int SESSION_SECONDS = 0;
int SESSION_MINUTES = 0;
int SESSION_HOURS = 0;
int BCRYPT_PRIORITY = 2;
int BCRYPT_MIN_PASSWORD;
int BCRYPT_MAX_PASSWORD;

int CYCLE_BSSL_CONTROL = 0;
int CYCLE_BSSL = 3;
int CYCLE_POWER = 4;
int CYCLE_CIPHER = 0;
int CYCLE_LOGS = 1;
int CYCLE_KEY = 0;
int CYCLE_BSSL_MAX = 6;
int CYCLE_POWER_MAX = 5;
int CYCLE_CIPHER_MAX = 2;
int CYCLE_LOGS_MAX = 3;
int CYCLE_KEY_MAX = 2;

//---------------------------------------------------------------------------
__fastcall TForm_Main::TForm_Main(TComponent* Owner)
        : TForm(Owner)
{
}
//---------------------------------------------------------------------------





void __fastcall TForm_Main::FormCreate(TObject *Sender)
{
char temp_string[200]="";
int round, bs, bc;

varinit = (globalvar *) malloc(sizeof(globalvar));

//binit(128, 0,"", 2,varinit);
bssl(3,&round, &bc, &bs, varinit,0);

  itoa(varinit->KEY_BUFFER,temp_string,10);
  Form_Main->Edit_Buffer->Text = temp_string;
  itoa(round,temp_string,10);
  Form_Main->Edit_Round->Text = temp_string;
  itoa(bc,temp_string,10);
  Form_Main->Edit_Bc->Text = temp_string;
  itoa(bs,temp_string,10);
  Form_Main->Edit_Bs->Text = temp_string;

NB_BYTE= varinit->NB_BYTE;
Edit_Bs->Text=IntToStr(NB_BYTE);
Label13->Caption= varinit->LIB_VERSION;


Label_Version->Caption = VERSION;
Form_Main->Caption = VERSION;
strcpy(temp_string,"Welcome to ");
strcat(temp_string,VERSION);
ListBox1->Clear();
ListBox1->Items->Add(temp_string);


Combo_Power->ItemIndex=4;
Combo_Keytype->ItemIndex=0;
Combo_Logs->ItemIndex=1;
Combo_Mode->ItemIndex=0;
Combo_Method->ItemIndex=0;
Combo_Random->ItemIndex=0;
Combo_Priority->ItemIndex=2;
Combo_Bssl->ItemIndex=3;

BCRYPT_MIN_PASSWORD = 8;
BCRYPT_MAX_PASSWORD = 16;


getcwd(PATH_MAIN, MAXPATH);

strcpy(PATH_LOGS,PATH_MAIN);
strcat(PATH_LOGS,"\\logs");

strcpy(PATH_DOC,PATH_MAIN);
strcat(PATH_DOC,"\\doc");

if (!DirectoryExists(PATH_LOGS))
  {
     if (!CreateDir(PATH_LOGS))
         ShowMessage("Cannot create the 'logs' directory");
  }

}

void __fastcall TForm_Main::SlideMouseDown(TObject *Sender,
      TMouseButton Button, TShiftState Shift, int X, int Y)
{
//Label_Keylength->Caption = itoa(pow(2,Slide->Position),"",10);
//Label_Keytitle->Caption = itoa(Slide->Position,"",10);

//Power(2,Slide->Position), "", 10);

}
//---------------------------------------------------------------------------









void __fastcall TForm_Main::Button_Crypt_SourceClick(TObject *Sender)
{
OpenDialog1->Title="SOURCE File";
OpenDialog1->Options << ofFileMustExist;
if(OpenDialog1->Execute())
         Edit_Crypt_Source->Text = OpenDialog1->FileName;
OpenDialog1->Options >> ofFileMustExist;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Crypt_DestClick(TObject *Sender)
{
OpenDialog1->Title="DESTINATION File";
if(OpenDialog1->Execute())
 Edit_Crypt_Dest->Text = OpenDialog1->FileName;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Crypt_KeyfileClick(TObject *Sender)
{
OpenDialog1->Title="KEY File";
if(OpenDialog1->Execute())
Edit_Crypt_Keyfile->Text = OpenDialog1->FileName;
}
//---------------------------------------------------------------------------



void __fastcall TForm_Main::Button_Crypt_ActionClick(TObject *Sender)
{

SESSION_SECONDS = 0;
SESSION_MINUTES = 0;
SESSION_HOURS = 0;

varinit->PROGRESS = 0;

Form_Main->RichEdit1->Clear();

thbcrypt *test = new thbcrypt;
test->Resume();

Form_Main->Button_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Decrypt_Action->Enabled = FALSE;
Form_Main->Button_Hide_Action->Enabled = FALSE;
Form_Main->Button_Keyfile_Action->Enabled = FALSE;
Form_Main->Button_Text_Stop->Enabled = FALSE;
Form_Main->Button_Text_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Text_Decrypt_Action->Enabled = FALSE;
Form_Main->Panel_Text->Visible = FALSE;
Form_Main->Button_Text_Crypt->Enabled = FALSE;
Form_Main->Button_Text_Decrypt->Enabled = FALSE;
Form_Main->Button_Crypt_Stop->Enabled = TRUE;


}
//---------------------------------------------------------------------------

void __fastcall thbcrypt::progress(void)

{
  varinit->PROGRESS=100;
  Form_Main->ProgressBar1->Position = 100;
}

void __fastcall thbcrypt::button_end(void)

{
   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Text_Stop->Enabled = TRUE;
   Form_Main->Button_Text_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Crypt->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt->Enabled = TRUE;
}


__fastcall thbcrypt::thbcrypt() : TThread(True)
{
if (0 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpLowest;

if (1 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpLower;

if (2 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpNormal;

if (3 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpHigher;

if (4 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpHighest;

  FreeOnTerminate = True;

//tpLowest	The thread's priority is two points below normal.
//tpLower	The thread's priority is one point below normal.
//tpNormal	The thread has normal priority.
//tpHigher	The thread's priority is one point above normal.
//tpHighest	The thread's priority is two points above normal.
//tpTimeCritical	The thread gets highest priority.
}

void __fastcall thbcrypt::Execute()
{
int power, bc, bs, mode, method, round, action, keylength, random,
    keytype, i;
char buf[200]="";
unsigned char *password;
int rename = 0;
char logs[MAXPATH]="";

strcpy(logs,PATH_LOGS);
strcat(logs,"\\bcrypt.log");

Form_Main->ListBox1->Clear();



bc = atoi(Form_Main->Edit_Bc->Text.c_str());
bs = atoi(Form_Main->Edit_Bs->Text.c_str());
round = atoi(Form_Main->Edit_Round->Text.c_str());
keylength = atoi(Form_Main->Label_Keylength->Caption.c_str());

if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Quiet") == 0)
        mode = 0;
   else
        {
        if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Verbose") == 0)
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

if (Form_Main->Combo_Mode->ItemIndex == 0)
        action = 0;
else
        action = 2;

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

if (strcmp(Form_Main->Edit_Crypt_Source->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a SOURCE FILE.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
   return;
   }
else
{
  if (!FileExists(Form_Main->Edit_Crypt_Source->Text.c_str()))
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("SOURCE FILE doesn't exist.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
   return;
   }
}

if (strcmp(Form_Main->Edit_Crypt_Dest->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a DESTINATION FILE.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
   return;
   }

if (1 == keytype)
   {
    if (strcmp(Form_Main->Edit_Crypt_Keyfile->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a KEY FILE.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
   return;
   }

   if (!FileExists(Form_Main->Edit_Crypt_Keyfile->Text.c_str()))
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("KEY FILE doesn't exist.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
   return;
   }

  }

if (0 == keytype)
   {

        if (strcmp(Form_Main->Edit_Crypt_Password->Text.c_str(),"") == 0)
           {
           Form_Main->ListBox1->Items->Add("ERROR.");
           Form_Main->ListBox1->Items->Add("Please enter a password");
           Synchronize((TThreadMethod)&button_end);
           Form_Main->Button_Crypt_Stop->Enabled = FALSE;
           return;
           }


        if (Form_Main->Edit_Crypt_Password->Text.Length() < BCRYPT_MIN_PASSWORD)
           {
           Form_Main->ListBox1->Items->Add("ERROR.");
           Form_Main->ListBox1->Items->Add("Password too short");
           Synchronize((TThreadMethod)&button_end);
           Form_Main->Button_Crypt_Stop->Enabled = FALSE;
           return;
           }

       Form_Main->ListBox1->Items->Add("Using Password");
   }
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

if (FileExists(logs))
      DeleteFile(logs);

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
          if (IDCANCEL == Application->MessageBox("TEMPORY file already exists. Do you want to Overwrite it?", "Overwriting Files", MB_OKCANCEL))
           {
            Form_Main->ListBox1->Items->Add("ERROR.");
            Form_Main->ListBox1->Items->Add("Can't rename. Filename already exists");
            Synchronize((TThreadMethod)&button_end);
            Form_Main->Button_Crypt_Stop->Enabled = FALSE;
            return;
           }
          else
           DeleteFile(source);
         }
        RenameFile(Form_Main->Edit_Crypt_Source->Text.c_str(), source);
        Form_Main->ListBox1->Items->Add("Renaming File Done.");
       }
    else
       {
       if (FileExists(Form_Main->Edit_Crypt_Dest->Text.c_str()))
         {

        if (IDCANCEL == Application->MessageBox("Destination file already exists. Do you want to Overwrite it?", "Overwriting Files", MB_OKCANCEL))
           {
          Form_Main->ListBox1->Items->Add("ERROR.");
          Form_Main->ListBox1->Items->Add("Destination File already exists");
          Synchronize((TThreadMethod)&button_end);
          Form_Main->Button_Crypt_Stop->Enabled = FALSE;
          return;
           }
        else
              DeleteFile(Form_Main->Edit_Crypt_Dest->Text.c_str());

         }
       }


    Form_Main->ListBox1->Refresh();
    Form_Main->Timer1->Enabled = TRUE;

    binit(keylength, random,logs,1,varinit);
    password = (unsigned char *)malloc(varinit->NB_CHAR);

    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Initialisation Done");
    Form_Main->ListBox1->Items->Add("Please Wait...");

    varinit->MISC = 0;

    if (Form_Main->Check_Round->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_ROUND;
         Form_Main->ListBox1->Items->Add("Dynamic Round");
        }

    if (Form_Main->Check_Shuffle->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_SHUFFLE;
         Form_Main->ListBox1->Items->Add("Dynamic Block Shuffle");
        }

    if (Form_Main->Check_Swap->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_SWAP;
      Form_Main->ListBox1->Items->Add("Dynamic Modulo Swap");
     }

    if (Form_Main->Check_Buffer->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_BUFFER;
      Form_Main->ListBox1->Items->Add("Dynamic Key Buffer");
     }

    varinit->KEY_BUFFER = atoi(Form_Main->Edit_Buffer->Text.c_str());

    if (Form_Main->Edit_Crypt_Password->Text.Length() > varinit->NB_CHAR)
      {
        i = varinit->NB_CHAR;
        Form_Main->ListBox1->Items->Add("Password length reduced.");
      }
    else
        i = Form_Main->Edit_Crypt_Password->Text.Length();

    strncpy(password, Form_Main->Edit_Crypt_Password->Text.c_str(), i);

    if (bfile (action,source,dest, Form_Main->Edit_Crypt_Keyfile->Text.c_str(),password, i,
          power, round, bc, bs, method, mode, varinit) == 0)
    {
            Form_Main->Timer1->Enabled = FALSE;
            Form_Main->ListBox1->Items->Add("");
            Form_Main->ListBox1->Items->Add("ERROR.");
            Form_Main->ListBox1->Items->Add("Please Look at the ADVANCED LOGS");
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
      Form_Main->Timer1->Enabled = FALSE;
      Synchronize((TThreadMethod)&button_end);
      Form_Main->Button_Crypt_Stop->Enabled = FALSE;
      return;
    }

   free(password);
   if (FileExists(logs))
           Form_Main->RichEdit1->Lines->LoadFromFile(logs);

   Synchronize((TThreadMethod)&progress);
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
}





void __fastcall TForm_Main::Button_Decrypt_ActionClick(TObject *Sender)
{
SESSION_SECONDS = 0;
SESSION_MINUTES = 0;
SESSION_HOURS = 0;

Form_Main->RichEdit1->Clear();

thdecrypt *test = new thdecrypt;
test->Resume();

Form_Main->Button_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Decrypt_Action->Enabled = FALSE;
Form_Main->Button_Hide_Action->Enabled = FALSE;
Form_Main->Button_Keyfile_Action->Enabled = FALSE;
Form_Main->Button_Text_Stop->Enabled = FALSE;
Form_Main->Button_Text_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Text_Decrypt_Action->Enabled = FALSE;
Form_Main->Panel_Text->Visible = FALSE;
Form_Main->Button_Text_Crypt->Enabled = FALSE;
Form_Main->Button_Text_Decrypt->Enabled = FALSE;
Form_Main->Button_Decrypt_Stop->Enabled = TRUE;
}

void __fastcall thdecrypt::progress(void)

{
  varinit->PROGRESS=100;
  Form_Main->ProgressBar1->Position = 100;
}

void __fastcall thdecrypt::button_end(void)

{
   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Text_Stop->Enabled = TRUE;
   Form_Main->Button_Text_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Crypt->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt->Enabled = TRUE;
}

__fastcall thdecrypt::thdecrypt() : TThread(True)
{
if (0 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpLowest;

if (1 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpLower;

if (2 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpNormal;

if (3 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpHigher;

if (4 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpHighest;

  FreeOnTerminate = True;
//tpIdle	The thread executes only when the system is idle. Windows won't interrupt other threads to execute a thread with tpIdle priority.
//tpLowest	The thread's priority is two points below normal.
//tpLower	The thread's priority is one point below normal.
//tpNormal	The thread has normal priority.
//tpHigher	The thread's priority is one point above normal.
//tpHighest	The thread's priority is two points above normal.
//tpTimeCritical	The thread gets highest priority.
}

void __fastcall thdecrypt::Execute()
{
 int power, bc, bs, mode, method, round, action, keylength, random,
     keytype, i;
   char buf[200]="";
   unsigned char *password;
   char logs[MAXPATH]="";

strcpy(logs,PATH_LOGS);
strcat(logs,"\\decrypt.log");

Form_Main->ListBox1->Clear();

bc = atoi(Form_Main->Edit_Bc->Text.c_str());
bs = atoi(Form_Main->Edit_Bs->Text.c_str());
round = atoi(Form_Main->Edit_Round->Text.c_str());
keylength = atoi(Form_Main->Label_Keylength->Caption.c_str());



if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Quiet") == 0)
        mode = 0;
   else
        {
        if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Verbose") == 0)
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

if (Form_Main->Combo_Mode->ItemIndex == 0)
        action = 1;
else
        action = 3;

if (strcmp(Form_Main->Combo_Random->Text.c_str(),"ISAAC") == 0)
        random = 1;
   else
        random = 0;

if (strcmp(Form_Main->Combo_Keytype->Text.c_str(),"Password") == 0)
        keytype = 0;
   else
        keytype = 1;

char* source = StrNew(Form_Main->Edit_Decrypt_Source->Text.c_str());
char* dest = StrNew(Form_Main->Edit_Decrypt_Dest->Text.c_str());
char* keyfile = StrNew(Form_Main->Edit_Decrypt_Keyfile->Text.c_str());

if (strcmp(Form_Main->Edit_Decrypt_Source->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a SOURCE FILE.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Decrypt_Stop->Enabled = FALSE;
   return;
   }
else
{
  if (!FileExists(Form_Main->Edit_Decrypt_Source->Text.c_str()))
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("SOURCE FILE doesn't exist.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Decrypt_Stop->Enabled = FALSE;
   return;
   }


}



if (strcmp(Form_Main->Edit_Decrypt_Dest->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a DESTINATION FILE.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Decrypt_Stop->Enabled = FALSE;
   return;
   }

if (1 == keytype)
   {
    if (strcmp(Form_Main->Edit_Decrypt_Keyfile->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a KEY FILE.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Decrypt_Stop->Enabled = FALSE;
   return;
   }


 if (!FileExists(Form_Main->Edit_Decrypt_Keyfile->Text.c_str()))
      {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("KEY FILE doesn't exist.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Crypt_Stop->Enabled = FALSE;
   return;
   }

  }

if (0 == keytype)
   {

        if (strcmp(Form_Main->Edit_Decrypt_Password->Text.c_str(),"") == 0)
           {
           Form_Main->ListBox1->Items->Add("ERROR.");
           Form_Main->ListBox1->Items->Add("Please enter a password");
           Synchronize((TThreadMethod)&button_end);
           Form_Main->Button_Crypt_Stop->Enabled = FALSE;
           return;
           }

        if (Form_Main->Edit_Decrypt_Password->Text.Length() < BCRYPT_MIN_PASSWORD)
           {
           Form_Main->ListBox1->Items->Add("ERROR.");
           Form_Main->ListBox1->Items->Add("Password too short");
           Synchronize((TThreadMethod)&button_end);
           Form_Main->Button_Crypt_Stop->Enabled = FALSE;
           return;
           }

       Form_Main->ListBox1->Items->Add("Using Password");
   }
   else
      {
        strcpy(buf,"Using Keyfile = ");
        strcat(buf,keyfile);
        Form_Main->ListBox1->Items->Add(buf);
      }

Form_Main->ListBox1->Items->Add("DECrypting in Progress...");

if (FileExists(logs))
      DeleteFile(logs);

Form_Main->ListBox1->Items->Add("Old logs deleted.");



if (
   (keytype == 1) || (strcmp(Form_Main->Edit_Decrypt_Password->Text.c_str(),"") != 0)
   )
   {

    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Working...");
    Form_Main->ListBox1->Items->Add("");


    if (strcmp(Form_Main->Edit_Decrypt_Source->Text.c_str(),Form_Main->Edit_Decrypt_Dest->Text.c_str()) == 0)
        {
         strcat(source, ".BUG");
         Form_Main->ListBox1->Items->Add("Source and Destination filename are the same.");
         Form_Main->ListBox1->Items->Add("Renaming Source to:");
         Form_Main->ListBox1->Items->Add(source);

         if (FileExists(source))
         {
           if (IDCANCEL == Application->MessageBox("TEMPORY file already exists. Do you want to Overwrite it?", "Overwriting Files", MB_OKCANCEL))
           {
            Form_Main->ListBox1->Items->Add("ERROR.");
            Form_Main->ListBox1->Items->Add("Can't rename. Filename already exists");
            Synchronize((TThreadMethod)&button_end);
            Form_Main->Button_Decrypt_Stop->Enabled = FALSE;
            return;
           }
          else
           DeleteFile(source);
         }

         RenameFile(Form_Main->Edit_Decrypt_Source->Text.c_str(), source);
         Form_Main->ListBox1->Items->Add("Done.");
        }
    else
       {
         if (FileExists(Form_Main->Edit_Decrypt_Dest->Text.c_str()))
         {
         if (IDCANCEL == Application->MessageBox("Destination file already exists. Do you want to Overwrite it?", "Overwriting Files", MB_OKCANCEL))
           {
          Form_Main->ListBox1->Items->Add("ERROR.");
          Form_Main->ListBox1->Items->Add("Destination File already exists");
          Synchronize((TThreadMethod)&button_end);
          Form_Main->Button_Decrypt_Stop->Enabled = FALSE;
          return;
           }
        else
              DeleteFile(Form_Main->Edit_Decrypt_Dest->Text.c_str());
         }
       }
    Form_Main->ListBox1->Refresh();

    Form_Main->Timer1->Enabled = TRUE;

    binit(keylength, random,logs, 1,varinit);

    password = (unsigned char *)malloc(varinit->NB_CHAR);


        Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Initialisation Done");
    Form_Main->ListBox1->Items->Add("Please Wait...");
    varinit->MISC = 0;

    if (Form_Main->Check_Round->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_ROUND;
         Form_Main->ListBox1->Items->Add("Dynamic Round");
        }

    if (Form_Main->Check_Shuffle->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_SHUFFLE;
         Form_Main->ListBox1->Items->Add("Dynamic Block Shuffle");
        }

    if (Form_Main->Check_Swap->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_SWAP;
      Form_Main->ListBox1->Items->Add("Dynamic Modulo Swap");
     }

    if (Form_Main->Check_Buffer->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_BUFFER;
      Form_Main->ListBox1->Items->Add("Dynamic Key Buffer");
     }

    varinit->KEY_BUFFER = atoi(Form_Main->Edit_Buffer->Text.c_str());



    if (Form_Main->Edit_Decrypt_Password->Text.Length() > varinit->NB_CHAR)
       {
        i = varinit->NB_CHAR;
        Form_Main->ListBox1->Items->Add("Password length reduced.");
       }
    else
        i = Form_Main->Edit_Decrypt_Password->Text.Length();

    strncpy(password, Form_Main->Edit_Decrypt_Password->Text.c_str(), i);

    if (bfile (action,source,dest, Form_Main->Edit_Decrypt_Keyfile->Text.c_str(),password, i,
          power, round, bc, bs, method, mode, varinit) == 0)
    {
     Form_Main->Timer1->Enabled = FALSE;
     Form_Main->ListBox1->Items->Add("");
     Form_Main->ListBox1->Items->Add("ERROR.");
     Form_Main->ListBox1->Items->Add("Please Look at the ADVANCED LOGS");
     }
     else
     {
      Form_Main->Timer1->Enabled = FALSE;
      Form_Main->ListBox1->Items->Add("");
      Form_Main->ListBox1->Items->Add("Time To Complete: ");
      Form_Main->ListBox1->Items->Add(Form_Main->Label_Logs_Time->Caption);
      Form_Main->ListBox1->Items->Add("Done !");
      Form_Main->ListBox1->Items->Add("");
      Form_Main->Edit_Decrypt_Password->Clear();
     }

     }
   else
   {
    Form_Main->ListBox1->Items->Add("ERROR.");
    Form_Main->ListBox1->Items->Add("Password Misspelled.");
    Form_Main->Timer1->Enabled = FALSE;
    Synchronize((TThreadMethod)&button_end);
    Form_Main->Button_Decrypt_Stop->Enabled = FALSE;
    return;
   }

   free(password);

if (FileExists(logs))
   Form_Main->RichEdit1->Lines->LoadFromFile(logs);

   Synchronize((TThreadMethod)&progress);
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Decrypt_Stop->Enabled = FALSE;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Decrypt_SourceClick(TObject *Sender)
{
OpenDialog1->Title="SOURCE File";
OpenDialog1->Options << ofFileMustExist;
if(OpenDialog1->Execute())
        Edit_Decrypt_Source->Text = OpenDialog1->FileName;
OpenDialog1->Options >> ofFileMustExist;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Decrypt_DestClick(TObject *Sender)
{
OpenDialog1->Title="DESTINATION File";
if(OpenDialog1->Execute())
 Edit_Decrypt_Dest->Text = OpenDialog1->FileName;        
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Decrypt_KeyfileClick(TObject *Sender)
{
OpenDialog1->Title="KEY File";
if(OpenDialog1->Execute())
 Edit_Decrypt_Keyfile->Text = OpenDialog1->FileName;        
}
//---------------------------------------------------------------------------


void __fastcall TForm_Main::Edit_Decrypt_KeyfileChange(TObject *Sender)
{
if (strcmp(Combo_Keytype->Text.c_str(),"Password") == 0)
   {
        Edit_Crypt_Keyfile->Visible = FALSE;
        //Button1->Visible = FALSE;
        //Label6->Visible = TRUE;
        //Label7->Visible = TRUE;
        Edit_Crypt_Password->Visible = TRUE;
        Edit_Crypt_Verif->Visible = TRUE;
   }
   else
   {
        Edit_Crypt_Keyfile->Visible = TRUE;
        Edit_Crypt_Password->Visible = FALSE;
        Edit_Crypt_Verif->Visible = FALSE;

   }
}
//---------------------------------------------------------------------------






//---------------------------------------------------------------------------


void __fastcall TForm_Main::Combo_KeytypeChange(TObject *Sender)
{
if (strcmp(Combo_Keytype->Text.c_str(),"Password") == 0)
   {
        Edit_Crypt_Keyfile->Visible = FALSE;
        Button_Crypt_Keyfile->Visible = FALSE;
        Label_Crypt_Keyfile->Visible = FALSE;
        Edit_Crypt_Password->Visible = TRUE;
        Edit_Crypt_Verif->Visible = TRUE;
        Label_Crypt_Password->Visible = TRUE;
        Label_Crypt_Verif->Visible = TRUE;


        Edit_Decrypt_Keyfile->Visible = FALSE;
        Button_Decrypt_Keyfile->Visible = FALSE;
        Label_Decrypt_Keyfile->Visible = FALSE;
        Edit_Decrypt_Password->Visible = TRUE;
        Label_Decrypt_Password->Visible = TRUE;

        Edit_Text_Keyfile->Visible = FALSE;
        Button_Text_Keyfile->Visible = FALSE;
        Label_Text_Keyfile->Visible = FALSE;
        Edit_Text_Password->Visible = TRUE;
        Edit_Text_Verif->Visible = TRUE;
        Label_Text_Password->Visible = TRUE;
        Label_Text_Verif->Visible = TRUE;

        Form_Main->Speed_Keytype->Caption="Password";
        CYCLE_KEY=0;
}
else
{
        Edit_Crypt_Keyfile->Visible = TRUE;
        Button_Crypt_Keyfile->Visible = TRUE;
        Label_Crypt_Keyfile->Visible = TRUE;
        Edit_Crypt_Password->Visible = FALSE;
        Edit_Crypt_Verif->Visible = FALSE;
        Label_Crypt_Password->Visible = FALSE;
        Label_Crypt_Verif->Visible = FALSE;

        Edit_Decrypt_Keyfile->Visible = TRUE;
        Button_Decrypt_Keyfile->Visible = TRUE;
        Label_Decrypt_Keyfile->Visible = TRUE;
        Edit_Decrypt_Password->Visible = FALSE;
        Label_Decrypt_Password->Visible = FALSE;

        Edit_Text_Keyfile->Visible = TRUE;
        Button_Text_Keyfile->Visible = TRUE;
        Label_Text_Keyfile->Visible = TRUE;
        Edit_Text_Password->Visible = FALSE;
        Edit_Text_Verif->Visible = FALSE;
        Label_Text_Password->Visible = FALSE;
        Label_Text_Verif->Visible = FALSE;

        Form_Main->Speed_Keytype->Caption="Keyfile";
        CYCLE_KEY=1;
}
   }
//---------------------------------------------------------------------------



void __fastcall TForm_Main::Button3Click(TObject *Sender)
{
RichEdit1->Visible=FALSE;
ListBox1->Visible=TRUE;
Button3->Enabled = False;
Button4->Enabled = True;
GroupBox4->Caption="Basic Logs";
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button4Click(TObject *Sender)
{
RichEdit1->Visible=TRUE;
ListBox1->Visible=FALSE;
Button3->Enabled = True;
Button4->Enabled = False;
GroupBox4->Caption="Advanced Logs";
}
//---------------------------------------------------------------------------




void __fastcall TForm_Main::Button5Click(TObject *Sender)
{
OpenDialog1->Title="KEY File";
if(OpenDialog1->Execute())
 Edit_Keyfile_File->Text = OpenDialog1->FileName;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Radio_Keyfile_RandomClick(TObject *Sender)
{
Edit_Keyfile_Password->Enabled = FALSE;
Edit_Keyfile_Password->Color = clSilver;
Radio_Keyfile_Random->Font->Color=clWhite;
Radio_Keyfile_Password->Font->Color=clBlack;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Radio_Keyfile_PasswordClick(TObject *Sender)
{
Edit_Keyfile_Password->Enabled = TRUE;
Edit_Keyfile_Password->Color = clWhite;
Radio_Keyfile_Random->Font->Color=clBlack;
Radio_Keyfile_Password->Font->Color=clWhite;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::BitBtn2Click(TObject *Sender)
{
OpenDialog1->Title="View BMP";
OpenDialog1->Options << ofFileMustExist;
RichEdit2->Visible = FALSE;
OpenDialog1->Filter="BMP files (*.bmp)|*.BMP|JPEG files (*.jpg)|*.JPG";
if(OpenDialog1->Execute())
 {
  Image1->Stretch = TRUE;
  Image1->Picture->LoadFromFile(OpenDialog1->FileName);
  Image1->Visible=TRUE;
 }
OpenDialog1->Options >> ofFileMustExist;
OpenDialog1->Filter="|";
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::BitBtn1Click(TObject *Sender)
{
OpenDialog1->Title="View File";
Image1->Visible=FALSE;
OpenDialog1->Options << ofFileMustExist;
if(OpenDialog1->Execute())
  {
    RichEdit2->Lines->LoadFromFile(OpenDialog1->FileName);
    RichEdit2->Visible = TRUE;
  }
OpenDialog1->Options >> ofFileMustExist;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Radio_Hide_HideClick(TObject *Sender)
{
  Radio_Hide_Hide->Font->Color=clWhite;
  Radio_Hide_Extract->Font->Color=clBlack;
  Button_Hide_Action->Caption="HIDE";
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Radio_Hide_ExtractClick(TObject *Sender)
{
 Radio_Hide_Hide->Font->Color=clBlack;
 Radio_Hide_Extract->Font->Color=clWhite;
 Button_Hide_Action->Caption="EXTRACT";
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Radio_Hide_EndClick(TObject *Sender)
{
 Radio_Hide_End->Font->Color=clWhite;
 Radio_Hide_Begining->Font->Color=clBlack;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Radio_Hide_BeginingClick(TObject *Sender)
{
 Radio_Hide_End->Font->Color=clBlack;
 Radio_Hide_Begining->Font->Color=clWhite;
}
//---------------------------------------------------------------------------


void __fastcall TForm_Main::SpeedButton1Click(TObject *Sender)
{
if (RichEdit_Text->Modified == TRUE)
 {
  if (IDCANCEL == Application->MessageBox("Current data will be lost. Are You sure ?", "Data have not been saved before", MB_OKCANCEL))
    return;
 }
 
RichEdit_Text->Clear();

}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::SpeedButton2Click(TObject *Sender)
{
OpenDialog1->Title="Load File";
OpenDialog1->Options << ofFileMustExist;

if(OpenDialog1->Execute())
        RichEdit_Text->Lines->LoadFromFile(OpenDialog1->FileName);

OpenDialog1->Options >> ofFileMustExist;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::SpeedButton3Click(TObject *Sender)
{
OpenDialog1->Title="Save File";
if ((RichEdit_Text->Modified == FALSE) || (strcmp(RichEdit_Text->Text.c_str(),"") == 0))
   {
    ListBox1->Items->Add("No changes. No need to save the file.");
    return;
   }

if(OpenDialog1->Execute())
 {
  if (FileExists(OpenDialog1->FileName))
    {
if (IDCANCEL == Application->MessageBox("Do you want to Overwrite the file ?", "Overwriting Files", MB_OKCANCEL))
   {
     ListBox1->Items->Add("ERROR");
     ListBox1->Items->Add("Cannot Save file. Filename already exists");
   }
else
      RichEdit_Text->Lines->SaveToFile(OpenDialog1->FileName);
    }
  else
        RichEdit_Text->Lines->SaveToFile(OpenDialog1->FileName);
  }
}
//---------------------------------------------------------------------------



void __fastcall TForm_Main::Button_Hide_ActionClick(TObject *Sender)
{
SESSION_SECONDS = 0;
SESSION_MINUTES = 0;
SESSION_HOURS = 0;

Form_Main->RichEdit1->Clear();

thbhide *test = new thbhide;
test->Resume();

Form_Main->Button_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Decrypt_Action->Enabled = FALSE;
Form_Main->Button_Hide_Action->Enabled = FALSE;
Form_Main->Button_Keyfile_Action->Enabled = FALSE;
Form_Main->Button_Text_Stop->Enabled = FALSE;
Form_Main->Button_Text_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Text_Decrypt_Action->Enabled = FALSE;
Form_Main->Panel_Text->Visible = FALSE;
Form_Main->Button_Text_Crypt->Enabled = FALSE;
Form_Main->Button_Text_Decrypt->Enabled = FALSE;
Form_Main->Button_Hide_Stop->Enabled = TRUE;
}

void __fastcall thbhide::progress(void)

{
  varinit->PROGRESS=100;
  Form_Main->ProgressBar1->Position = 100;
}

void __fastcall thbhide::button_end(void)

{
   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Text_Stop->Enabled = TRUE;
   Form_Main->Button_Text_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Crypt->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt->Enabled = TRUE;
}

__fastcall thbhide::thbhide() : TThread(True)
{
if (0 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpLowest;

if (1 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpLower;

if (2 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpNormal;

if (3 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpHigher;

if (4 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpHighest;

  FreeOnTerminate = True;
//tpIdle	The thread executes only when the system is idle. Windows won't interrupt other threads to execute a thread with tpIdle priority.
//tpLowest	The thread's priority is two points below normal.
//tpLower	The thread's priority is one point below normal.
//tpNormal	The thread has normal priority.
//tpHigher	The thread's priority is one point above normal.
//tpHighest	The thread's priority is two points above normal.
//tpTimeCritical	The thread gets highest priority.
}

void __fastcall thbhide::Execute()
{
int mode, random, option, hide, check_error;
char logs[MAXPATH]="";

strcpy(logs,PATH_LOGS);
strcat(logs,"\\hide.log");

Form_Main->ListBox1->Clear();

if (strcmp(Form_Main->Edit_Hide_Source->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a SOURCE FILE.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Hide_Stop->Enabled = FALSE;
   return;
   }

if (strcmp(Form_Main->Edit_Hide_Dest->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a DESTINATION FILE.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Hide_Stop->Enabled = FALSE;
   return;
   }

if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Quiet") == 0)
        mode = 0;
   else
        {
        if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Verbose") == 0)
                mode = 1;
        else
                mode = 2;
        }

if (strcmp(Form_Main->Combo_Random->Text.c_str(),"ISAAC") == 0)
        random = 1;
   else
        random = 0;

if (Form_Main->Radio_Hide_Hide->Checked == TRUE)
        hide = 1;
    else
        hide = 0;

if (Form_Main->Radio_Hide_End->Checked == TRUE)
        option = 1;
    else
        option = 0;

Form_Main->ListBox1->Items->Add("Checking Files...");

if (strcmp(Form_Main->Edit_Hide_Source->Text.c_str(),Form_Main->Edit_Hide_Dest->Text.c_str()) == 0)
        {
         Form_Main->ListBox1->Items->Add("ERROR.");
         Form_Main->ListBox1->Items->Add("SOURCE and DEST file cannot be the same");
         Synchronize((TThreadMethod)&button_end);
         Form_Main->Button_Hide_Stop->Enabled = FALSE;
         return;
         }

if ((FileExists(Form_Main->Edit_Hide_Dest->Text.c_str()))  && (0 == hide))
   {
    Form_Main->ListBox1->Items->Add("ERROR.");
    Form_Main->ListBox1->Items->Add("Cannot Extract. DEST file already exists");
    Synchronize((TThreadMethod)&button_end);
    Form_Main->Button_Hide_Stop->Enabled = FALSE;
    return;
   }

Form_Main->ListBox1->Items->Add("Done.");
Form_Main->ListBox1->Items->Add("");

if (1 == hide)
        Form_Main->ListBox1->Items->Add("Extracting data in Progress...");
else
        Form_Main->ListBox1->Items->Add("Hiding data in Progress...");

 if (FileExists(logs))
      DeleteFile(logs);

Form_Main->ListBox1->Items->Add("Old logs deleted.");

Form_Main->Timer1->Enabled = TRUE;

binit(128, random,logs, 1,varinit);

check_error = 0;

if (1 == hide)
   {
  if (bcrypt_write_hide (option,Form_Main->Edit_Hide_Source->Text.c_str(),Form_Main->Edit_Hide_Dest->Text.c_str(), varinit, mode) == 0)
      check_error = 1;
   }
else
   {
   if (bcrypt_read_hide (option,Form_Main->Edit_Hide_Source->Text.c_str(),Form_Main->Edit_Hide_Dest->Text.c_str(), varinit, mode) == 0)
      check_error = 1;
   }

Form_Main->Timer1->Enabled = FALSE;
if (FileExists(logs))
Form_Main->RichEdit1->Lines->LoadFromFile(logs);

if (1 == check_error)
   {
    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("ERROR.");
    Form_Main->ListBox1->Items->Add("Please Look at the ADVANCED LOGS");
   }
   else
   {
    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Time To Complete: ");
    Form_Main->ListBox1->Items->Add(Form_Main->Label_Logs_Time->Caption);
    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Done !");
    Form_Main->ListBox1->Items->Add("");
   }

Synchronize((TThreadMethod)&progress);
Synchronize((TThreadMethod)&button_end);
Form_Main->Button_Hide_Stop->Enabled = FALSE;

}
//---------------------------------------------------------------------------


void __fastcall TForm_Main::Button7Click(TObject *Sender)
{
OpenDialog1->Title="SOURCE File";
OpenDialog1->Options << ofFileMustExist;
if(OpenDialog1->Execute())
        Edit_Hide_Source->Text = OpenDialog1->FileName;
OpenDialog1->Options >> ofFileMustExist;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button8Click(TObject *Sender)
{
OpenDialog1->Title="DESTINATION File";
if(OpenDialog1->Execute())
 Edit_Hide_Dest->Text = OpenDialog1->FileName;        
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Keyfile_ActionClick(TObject *Sender)
{
SESSION_SECONDS = 0;
SESSION_MINUTES = 0;
SESSION_HOURS = 0;

Form_Main->RichEdit1->Clear();

thbkey *test = new thbkey;
test->Resume();

Form_Main->Button_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Decrypt_Action->Enabled = FALSE;
Form_Main->Button_Hide_Action->Enabled = FALSE;
Form_Main->Button_Keyfile_Action->Enabled = FALSE;
Form_Main->Button_Text_Stop->Enabled = FALSE;
Form_Main->Button_Text_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Text_Decrypt_Action->Enabled = FALSE;
Form_Main->Panel_Text->Visible = FALSE;
Form_Main->Button_Text_Crypt->Enabled = FALSE;
Form_Main->Button_Text_Decrypt->Enabled = FALSE;
Form_Main->Button_Keyfile_Stop->Enabled = TRUE;
}

void __fastcall thbkey::progress(void)

{
  varinit->PROGRESS=100;
  Form_Main->ProgressBar1->Position = 100;
}

void __fastcall thbkey::button_end(void)

{
   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Text_Stop->Enabled = TRUE;
   Form_Main->Button_Text_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Crypt->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt->Enabled = TRUE;
}
__fastcall thbkey::thbkey() : TThread(True)
{
if (0 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpLowest;

if (1 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpLower;

if (2 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpNormal;

if (3 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpHigher;

if (4 == Form_Main->Combo_Priority->ItemIndex)
  Priority = tpHighest;

  FreeOnTerminate = True;
//tpIdle	The thread executes only when the system is idle. Windows won't interrupt other threads to execute a thread with tpIdle priority.
//tpLowest	The thread's priority is two points below normal.
//tpLower	The thread's priority is one point below normal.
//tpNormal	The thread has normal priority.
//tpHigher	The thread's priority is one point above normal.
//tpHighest	The thread's priority is two points above normal.
//tpTimeCritical	The thread gets highest priority.
}

void __fastcall thbkey::Execute()
{
int mode, random, random_method, round, keylength, i;
unsigned char *password;
char logs[MAXPATH]="";

strcpy(logs,PATH_LOGS);
strcat(logs,"\\keyfile.log");

Form_Main->ListBox1->Clear();

if (strcmp(Form_Main->Edit_Keyfile_File->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please enter a KEYFILE NAME.");
   Synchronize((TThreadMethod)&button_end);
   Form_Main->Button_Keyfile_Stop->Enabled = FALSE;
   return;
   }

if (Form_Main->Radio_Keyfile_Random->Checked == TRUE)
    random_method = 1;
else
   {
    random_method = 0;

    if (Form_Main->Edit_Keyfile_Password->Text.Length() < 8)
        {
           Form_Main->ListBox1->Items->Add("ERROR.");
           Form_Main->ListBox1->Items->Add("Password too short");
           Synchronize((TThreadMethod)&button_end);
           Form_Main->Button_Keyfile_Stop->Enabled = FALSE;
           return;
        }
   }

round = atoi(Form_Main->Edit_Round->Text.c_str());
keylength = atoi(Form_Main->Label_Keylength->Caption.c_str());


if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Quiet") == 0)
        mode = 0;
   else
        {
        if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Verbose") == 0)
                mode = 1;
        else
                mode = 2;
        }

if (strcmp(Form_Main->Combo_Random->Text.c_str(),"ISAAC") == 0)
        random = 1;
   else
        random = 0;

Form_Main->ListBox1->Items->Add("Checking File...");


if (FileExists(Form_Main->Edit_Keyfile_File->Text.c_str()))
         {
         if (IDCANCEL == Application->MessageBox("KEY file already exists. Do you want to Overwrite it?", "Overwriting Files", MB_OKCANCEL))
           {
          Form_Main->ListBox1->Items->Add("ERROR.");
          Form_Main->ListBox1->Items->Add("KEY File already exists");
          Synchronize((TThreadMethod)&button_end);
          Form_Main->Button_Keyfile_Stop->Enabled = FALSE;
          return;
           }
        else
              DeleteFile(Form_Main->Edit_Keyfile_File->Text.c_str());
         }

Form_Main->ListBox1->Items->Add("Done.");
Form_Main->ListBox1->Items->Add("");

Form_Main->ListBox1->Items->Add("Generating KEY in Progress...");
 if (FileExists(logs))
      DeleteFile(logs);

Form_Main->ListBox1->Items->Add("Old logs deleted.");

Form_Main->Timer1->Enabled = TRUE;

binit(keylength, random,logs, 1,varinit);

password = (unsigned char *)malloc(16);

    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Initialisation Done");
    Form_Main->ListBox1->Items->Add("Please Wait...");
    varinit->MISC = 0;

    if (Form_Main->Check_Round->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_ROUND;
         Form_Main->ListBox1->Items->Add("Dynamic Round");
        }

    if (Form_Main->Check_Shuffle->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_SHUFFLE;
         Form_Main->ListBox1->Items->Add("Dynamic Block Shuffle");
        }

    if (Form_Main->Check_Swap->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_SWAP;
      Form_Main->ListBox1->Items->Add("Dynamic Modulo Swap");
     }

    if (Form_Main->Check_Buffer->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_BUFFER;
      Form_Main->ListBox1->Items->Add("Dynamic Key Buffer");
     }

    varinit->KEY_BUFFER = atoi(Form_Main->Edit_Buffer->Text.c_str());


i = 0;

if (0 == random_method)
   {
    if (Form_Main->Edit_Keyfile_Password->Text.Length() > 16)
       {
           i = 16;
           Form_Main->ListBox1->Items->Add("Password length reduced.");
       }
    else
           i = Form_Main->Edit_Keyfile_Password->Text.Length();

    strncpy(password, Form_Main->Edit_Keyfile_Password->Text.c_str(), i);
   }

if (bkey_generator (password, i,
          round, Form_Main->Edit_Keyfile_File->Text.c_str(),0 , random_method, mode, varinit) == 0)
{
    Form_Main->Timer1->Enabled = FALSE;
    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("ERROR.");
    Form_Main->ListBox1->Items->Add("Please Look at the ADVANCED LOGS");
}
else
{
    Form_Main->Edit_Keyfile_Password->Clear();
    Form_Main->Timer1->Enabled = FALSE;
    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Time To Complete: ");
    Form_Main->ListBox1->Items->Add(Form_Main->Label_Logs_Time->Caption);
    Form_Main->ListBox1->Items->Add("Done !");
    Form_Main->ListBox1->Items->Add("");
}

free(password);
if (FileExists(logs))
Form_Main->RichEdit1->Lines->LoadFromFile(logs);

Synchronize((TThreadMethod)&progress);
Synchronize((TThreadMethod)&button_end);
Form_Main->Button_Keyfile_Stop->Enabled = FALSE;
}
//---------------------------------------------------------------------------




void __fastcall TForm_Main::BitBtn3Click(TObject *Sender)
{
//GroupBox6->Visible = TRUE;
//GroupBox6->BringToFront();

int i, mode, move, max, step, exit;

if (GroupBox6->Visible == FALSE)
{
srand(time(NULL)+ clock());
mode = rand()%4;

switch(mode)
      {
      case 0: move=1;
              i=-360;
              max=0;
              step=15;
              break;

      case 1: move=1;
              i=360;
              max=-0;
              step=-15;
              break;

      case 2 : move=2;
               i=-750;
               max=0;
               step=25;
               break;

      default: move=2;
               i=750;
               max=0;
               step=-25;
               break;

      }

      if (1 == move)
         {
          GroupBox6->Top = i;
          GroupBox6->Left = 0;
         }
      else
         {
          GroupBox6->Top = 0;
          GroupBox6->Left = i;
         }

      GroupBox6->Visible=True;
      GroupBox6->BringToFront();

      exit=0;

      do
      {
       if (1 ==  move)
               GroupBox6->Top = i;
       else
               GroupBox6->Left = i;

       i=i+step;
       GroupBox6->Refresh();
       GroupBox1->Refresh();
       GroupBox4->Refresh();
       GroupBox5->Refresh();
       Sleep(1);

       if (0 < step)
          {
          if (i > max) exit=1;
          }
       else
          {
          if (i < max) exit=1;
          }

      } while (FALSE == exit);

GroupBox1->Visible=False;
GroupBox4->Visible=False;
GroupBox5->Visible=False;
}
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button6Click(TObject *Sender)
{
int i, mode, move, max, step, exit;

if (GroupBox6->Visible == TRUE)
{
srand(time(NULL)+ clock());
mode = rand()%4;

switch(mode)
      {
      case 0: move=1;
              i=0;
              max=360;
              step=15;
              break;

      case 1: move=1;
              i=0;
              max=-360;
              step=-15;
              break;

      case 2 : move=2;
               i=0;
               max=750;
               step=25;
               break;

      default: move=2;
               i=0;
               max=-750;
               step=-25;
               break;

      }

      GroupBox6->Visible=True;
      GroupBox6->BringToFront();
      GroupBox1->Visible=TRUE;
      GroupBox4->Visible=TRUE;
      GroupBox5->Visible=TRUE;


      exit=0;

      do
      {
       if (1 ==  move)
               GroupBox6->Top = i;
       else
               GroupBox6->Left = i;

       i=i+step;
       GroupBox6->Refresh();
       GroupBox1->Refresh();
       GroupBox4->Refresh();
       GroupBox5->Refresh();
       Sleep(1);

       if (0 < step)
          {
          if (i > max) exit=1;
          }
       else
          {
          if (i < max) exit=1;
          }

      } while (FALSE == exit);

GroupBox6->Visible=False;
GroupBox1->BringToFront();
GroupBox4->BringToFront();
GroupBox5->BringToFront();
}


}
//---------------------------------------------------------------------------





void __fastcall TForm_Main::Button9Click(TObject *Sender)
{
char doc[MAX_PATH];

strcpy(doc,PATH_DOC);
strcat(doc,"\\bcrypt\\bcrypt.html");
strcat(doc,"\0");

OpenWebPage(doc);

RichEdit4->Text= "You should now see a Web Browser with the bcrypt help file.";
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("If you can't see it, you can still access the help file directly at:");
RichEdit4->Lines->Add(doc);
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("If the file above does not exist:");
RichEdit4->Lines->Add("Please check you are running bcrypt from its original location.");
RichEdit4->Lines->Add("If you still got a problem please go to the official WEB SITE for more information:");
RichEdit4->Lines->Add("http://www.bcrypt.com");
RichEdit4->Lines->Add("http://www.encryptsolutions.com");

}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button10Click(TObject *Sender)
{
char doc[MAX_PATH];

strcpy(doc,PATH_DOC);
strcat(doc,"\\bugs\\index.html");
strcat(doc,"\0");

OpenWebPage(doc);

RichEdit4->Text= "You should now see a Web Browser with the BUGS help file.";
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("If you can't see it, you can still access the help file directly at:");
RichEdit4->Lines->Add(doc);
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("If the file above does not exist:");
RichEdit4->Lines->Add("Please check you are running bcrypt from its original location.");
RichEdit4->Lines->Add("If you still got a problem please go to the official WEB SITE for more information:");
RichEdit4->Lines->Add("http://www.bcrypt.com");
RichEdit4->Lines->Add("http://www.encryptsolutions.com");
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button11Click(TObject *Sender)
{
char doc[MAX_PATH];

strcpy(doc,PATH_DOC);
strcat(doc,"\\cv\\cv_uk.html");
strcat(doc,"\0");


OpenWebPage(doc);

RichEdit4->Text= "You should now see a Web Browser with the CV file.";
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("If you can't see it, you can still access the help file directly at:");
RichEdit4->Lines->Add(doc);
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("If the file above does not exist:");
RichEdit4->Lines->Add("Please check you are running bcrypt from its original location.");
RichEdit4->Lines->Add("If you still got a problem please go to the official WEB SITE for more information:");
RichEdit4->Lines->Add("http://www.bcrypt.com");
RichEdit4->Lines->Add("http://www.encryptsolutions.com");

}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button12Click(TObject *Sender)
{
char doc[MAX_PATH];

strcpy(doc,PATH_DOC);
strcat(doc,"\\cv\\note_uk.html");
strcat(doc,"\0");


OpenWebPage(doc);

RichEdit4->Text= "You should now see a Web Browser with the Add Note file.";
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("If you can't see it, you can still access the help file directly at:");
RichEdit4->Lines->Add(doc);
RichEdit4->Lines->Add("");
RichEdit4->Lines->Add("If the file above does not exist:");
RichEdit4->Lines->Add("Please check you are running bcrypt from its original location.");
RichEdit4->Lines->Add("If you still got a problem please go to the official WEB SITE for more information:");
RichEdit4->Lines->Add("http://www.bcrypt.com");
RichEdit4->Lines->Add("http://www.encryptsolutions.com");

}
//---------------------------------------------------------------------------


void __fastcall TForm_Main::Edit_BsExit(TObject *Sender)
{
int i,j;

i=StrToInt(Edit_Bs->Text.c_str());

j = i / NB_BYTE;
j = j * NB_BYTE;

if (j < i)
        j = j + NB_BYTE;

if (0 == j) j = NB_BYTE;

Edit_Bs->Text = IntToStr(j);
}
//---------------------------------------------------------------------------


void __fastcall TForm_Main::Edit_RoundExit(TObject *Sender)
{
if (StrToInt(Edit_Round->Text.c_str()) == 0)
        Edit_Round->Text = IntToStr(2);
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Timer1Timer(TObject *Sender)
{
SESSION_SECONDS++;

if(varinit->PROGRESS <= 100)
 {
 ProgressBar1->Position = varinit->PROGRESS;
 }

 if (60 == SESSION_SECONDS)
   {
    SESSION_SECONDS = 0;
    SESSION_MINUTES++;
   }
if (60 == SESSION_MINUTES)
   {
    SESSION_MINUTES = 0;
    SESSION_HOURS++;
   }
if (24 == SESSION_HOURS)
   {
    SESSION_HOURS = 0;
   }

//TDate_Time->
if (10 > SESSION_HOURS)
        Label_Logs_Time->Caption = "0" + IntToStr(SESSION_HOURS);
else
        Label_Logs_Time->Caption = IntToStr(SESSION_HOURS);

if (10 > SESSION_MINUTES)
        Label_Logs_Time->Caption = Label_Logs_Time->Caption + ":0" + IntToStr(SESSION_MINUTES);
else
        Label_Logs_Time->Caption = Label_Logs_Time->Caption + ":" + IntToStr(SESSION_MINUTES);

if (10 > SESSION_SECONDS)
        Label_Logs_Time->Caption = Label_Logs_Time->Caption + ":0" + IntToStr(SESSION_SECONDS);
else
        Label_Logs_Time->Caption = Label_Logs_Time->Caption + ":" + IntToStr(SESSION_SECONDS);


}
//---------------------------------------------------------------------------


void __fastcall TForm_Main::Button_Crypt_StopClick(TObject *Sender)
{
varinit->MISC ^= BMASK_STOP;
Form_Main->Button_Crypt_Action->Enabled = TRUE;
Form_Main->Button_Decrypt_Action->Enabled = TRUE;
Form_Main->Button_Hide_Action->Enabled = TRUE;
Form_Main->Button_Keyfile_Action->Enabled = TRUE;
Form_Main->Button_Crypt_Stop->Enabled = FALSE;
}



void __fastcall TForm_Main::Button_Decrypt_StopClick(TObject *Sender)
{
varinit->MISC ^= BMASK_STOP;
Form_Main->Button_Crypt_Action->Enabled = TRUE;
Form_Main->Button_Decrypt_Action->Enabled = TRUE;
Form_Main->Button_Hide_Action->Enabled = TRUE;
Form_Main->Button_Keyfile_Action->Enabled = TRUE;
Form_Main->Button_Decrypt_Stop->Enabled = FALSE;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Keyfile_StopClick(TObject *Sender)
{
varinit->MISC ^= BMASK_STOP;
Form_Main->Button_Crypt_Action->Enabled = TRUE;
Form_Main->Button_Decrypt_Action->Enabled = TRUE;
Form_Main->Button_Hide_Action->Enabled = TRUE;
Form_Main->Button_Keyfile_Action->Enabled = TRUE;
Form_Main->Button_Keyfile_Stop->Enabled = FALSE;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Hide_StopClick(TObject *Sender)
{
varinit->MISC ^= BMASK_STOP;
Form_Main->Button_Crypt_Action->Enabled = TRUE;
Form_Main->Button_Decrypt_Action->Enabled = TRUE;
Form_Main->Button_Hide_Action->Enabled = TRUE;
Form_Main->Button_Keyfile_Action->Enabled = TRUE;
Form_Main->Button_Hide_Stop->Enabled = FALSE;        
}
//---------------------------------------------------------------------------


void __fastcall TForm_Main::Combo_ModeChange(TObject *Sender)
{
if (Combo_Mode->ItemIndex == 1)
 {
    Combo_Method->ItemIndex = 0;
    CYCLE_CIPHER = 0;
 }
else
 CYCLE_CIPHER = 1;
 
Form_Main->Choice_Info();
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Combo_MethodChange(TObject *Sender)
{
if ((Combo_Method->ItemIndex == 1) && (Combo_Mode->ItemIndex == 1))
 {
  Combo_Mode->ItemIndex = 0;
  CYCLE_CIPHER = 0;
 }
Choice_Info();

}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Text_StopClick(TObject *Sender)
{
varinit->MISC ^= BMASK_STOP;
Form_Main->Button_Crypt_Action->Enabled = TRUE;
Form_Main->Button_Decrypt_Action->Enabled = TRUE;
Form_Main->Button_Hide_Action->Enabled = TRUE;
Form_Main->Button_Keyfile_Action->Enabled = TRUE;
Form_Main->Panel_Text->Visible = FALSE;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Text_CryptClick(TObject *Sender)
{
if (strcmp(RichEdit_Text->Text.c_str(),"") == 0)
   {
    ListBox1->Items->Add("No data to crypt.");
    ListBox1->Items->Add("Please type something in the Text Editor first");
    return;
   }

Form_Main->Edit_Text_Verif->Visible = TRUE;
Form_Main->Label_Text_Verif->Visible = TRUE;
Form_Main->Button_Text_Crypt_Action->Visible = TRUE;
Form_Main->Button_Text_Crypt_Action->Enabled = TRUE;
Form_Main->Button_Text_Decrypt_Action->Enabled = FALSE;
Form_Main->Button_Text_Decrypt_Action->Visible = FALSE;
Form_Main->Panel_Text->Visible = TRUE;
Form_Main->Panel_Text->BringToFront();
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Text_KeyfileClick(TObject *Sender)
{
OpenDialog1->Title="KEY File";
if(OpenDialog1->Execute())
Edit_Text_Keyfile->Text = OpenDialog1->FileName;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Text_Crypt_ActionClick(TObject *Sender)
{

char *temp_bugs_clear="temp_edit_bugs1";
char *temp_bugs_crypted="temp_edit_bugs2";
SESSION_SECONDS = 0;
SESSION_MINUTES = 0;
SESSION_HOURS = 0;

varinit->PROGRESS = 0;

Form_Main->ListBox1->Items->Add("Crypting Text Editor in progress.");
Form_Main->ListBox1->Items->Add("");
Form_Main->ListBox1->Items->Add("Saving Texteditor data into 'temp_edit_bugs' file");
if (FileExists(temp_bugs_clear))
   {
    Form_Main->ListBox1->Items->Add("Removing previous temp files.");
    DeleteFile(temp_bugs_clear);
    DeleteFile(temp_bugs_crypted);
   }

RichEdit_Text->Lines->SaveToFile(temp_bugs_clear);

Form_Main->RichEdit1->Clear();

thtext_bcrypt *test = new thtext_bcrypt;
test->Resume();

Form_Main->Button_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Decrypt_Action->Enabled = FALSE;
Form_Main->Button_Hide_Action->Enabled = FALSE;
Form_Main->Button_Keyfile_Action->Enabled = FALSE;
Form_Main->Button_Text_Crypt_Action->Enabled = FALSE;

}



void __fastcall thtext_bcrypt::progress(void)

{
  varinit->PROGRESS=100;
  Form_Main->ProgressBar1->Position = 100;
}

void __fastcall thtext_bcrypt::button_end(void)

{
   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Text_Stop->Enabled = TRUE;
   Form_Main->Button_Text_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Crypt->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt->Enabled = TRUE;
}


__fastcall thtext_bcrypt::thtext_bcrypt() : TThread(True)
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

void __fastcall thtext_bcrypt::Execute()
{
int power, bc, bs, mode, method, round, action, keylength, random,
    keytype, i;
char buf[200]="";
char *source="temp_edit_bugs1";
char *dest="temp_edit_bugs2";

unsigned char *password;
char logs[MAXPATH]="";

strcpy(logs,PATH_LOGS);
strcat(logs,"\\editor_crypt.log");

Form_Main->ListBox1->Clear();



bc = atoi(Form_Main->Edit_Bc->Text.c_str());
bs = atoi(Form_Main->Edit_Bs->Text.c_str());
round = atoi(Form_Main->Edit_Round->Text.c_str());
keylength = atoi(Form_Main->Label_Keylength->Caption.c_str());

if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Quiet") == 0)
        mode = 0;
   else
        {
        if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Verbose") == 0)
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

/*
 *  Forcing to mode = ASCII and method = MEMORY
 */
method = 1;
action = 2;

if (strcmp(Form_Main->Combo_Random->Text.c_str(),"ISAAC") == 0)
        random = 1;
   else
        random = 0;

if (strcmp(Form_Main->Combo_Keytype->Text.c_str(),"Password") == 0)
        keytype = 0;
   else
        keytype = 1;

char* keyfile = StrNew(Form_Main->Edit_Text_Keyfile->Text.c_str());

if (1 == keytype)
   {
    if (strcmp(Form_Main->Edit_Text_Keyfile->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a KEY FILE.");
   Synchronize((TThreadMethod)&button_end);
   if (FileExists(dest))
       DeleteFile(dest);
   if (FileExists(source))
       DeleteFile(source);
   return;
   }

   if (!FileExists(Form_Main->Edit_Text_Keyfile->Text.c_str()))
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("KEY FILE doesn't exist.");
   Synchronize((TThreadMethod)&button_end);
   if (FileExists(dest))
       DeleteFile(dest);
   if (FileExists(source))
       DeleteFile(source);
   return;
   }

  }

if (0 == keytype)
   {
           if (strcmp(Form_Main->Edit_Text_Password->Text.c_str(),"") == 0)
           {
           Form_Main->ListBox1->Items->Add("ERROR.");
           Form_Main->ListBox1->Items->Add("Please enter a password");
           Synchronize((TThreadMethod)&button_end);
           if (FileExists(dest))
               DeleteFile(dest);
           if (FileExists(source))
               DeleteFile(source);
           return;
           }

        if (Form_Main->Edit_Text_Password->Text.Length() < BCRYPT_MIN_PASSWORD)
           {
           Form_Main->ListBox1->Items->Add("ERROR.");
           Form_Main->ListBox1->Items->Add("Password too short");
           Synchronize((TThreadMethod)&button_end);
           Form_Main->Button_Crypt_Stop->Enabled = FALSE;
           return;
           }

       Form_Main->ListBox1->Items->Add("Using Password");
   }
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

if (FileExists(logs))
      DeleteFile(logs);

if (
   (1 == keytype) || ((strcmp(Form_Main->Edit_Text_Password->Text.c_str(),"") != 0) &&
   (strcmp(Form_Main->Edit_Text_Password->Text.c_str(), Form_Main->Edit_Text_Verif->Text.c_str()) == 0))
   )

   {

    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Working...");
    Form_Main->ListBox1->Items->Add("");

    Form_Main->ListBox1->Refresh();
    Form_Main->Timer1->Enabled = TRUE;

    binit(keylength, random,logs,1,varinit);
    password = (unsigned char *)malloc(varinit->NB_CHAR);

        Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Initialisation Done");
    Form_Main->ListBox1->Items->Add("Please Wait...");
    varinit->MISC = 0;

    if (Form_Main->Check_Round->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_ROUND;
         Form_Main->ListBox1->Items->Add("Dynamic Round");
        }

    if (Form_Main->Check_Shuffle->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_SHUFFLE;
         Form_Main->ListBox1->Items->Add("Dynamic Block Shuffle");
        }

    if (Form_Main->Check_Swap->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_SWAP;
      Form_Main->ListBox1->Items->Add("Dynamic Modulo Swap");
     }

    if (Form_Main->Check_Buffer->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_BUFFER;
      Form_Main->ListBox1->Items->Add("Dynamic Key Buffer");
     }

    varinit->KEY_BUFFER = atoi(Form_Main->Edit_Buffer->Text.c_str());


    if (Form_Main->Edit_Text_Password->Text.Length() > varinit->NB_CHAR)
      {
        i = varinit->NB_CHAR;
        Form_Main->ListBox1->Items->Add("Password length reduced.");
      }
    else
        i = Form_Main->Edit_Text_Password->Text.Length();

    strncpy(password, Form_Main->Edit_Text_Password->Text.c_str(), i);

   if (bfile (action,source,dest, Form_Main->Edit_Text_Keyfile->Text.c_str(),password, i,
          power, round, bc, bs, method, mode, varinit) == 0)
    {
            Form_Main->Timer1->Enabled = FALSE;
            Form_Main->ListBox1->Items->Add("");
            Form_Main->ListBox1->Items->Add("ERROR.");
            Form_Main->ListBox1->Items->Add("Please Look at the ADVANCED LOGS");
    }
    else
    {
        Form_Main->ListBox1->Items->Add("Deleting tempory file:");
        Form_Main->ListBox1->Items->Add(source);
        DeleteFile(source);

        if (FileExists(dest))
           {
            Form_Main->RichEdit_Text->Lines->LoadFromFile(dest);
            DeleteFile(dest);
           }
        else
           {
            Form_Main->ListBox1->Items->Add("ERROR.");
            Form_Main->ListBox1->Items->Add("Cannot find tempory crypted file.");
           }
        Form_Main->Edit_Text_Password->Clear();
        Form_Main->Edit_Text_Verif->Clear();
        Form_Main->Timer1->Enabled = FALSE;
        Form_Main->ListBox1->Items->Add("");
        Form_Main->ListBox1->Items->Add("Time To Complete: ");
        Form_Main->ListBox1->Items->Add(Form_Main->Label_Logs_Time->Caption);
        Form_Main->ListBox1->Items->Add("Done !");
        Form_Main->ListBox1->Items->Add("");
        Form_Main->Panel_Text->Visible = FALSE;
    }
 }
  else
    {
      Form_Main->ListBox1->Items->Add("ERROR.");
      Form_Main->ListBox1->Items->Add("Password Misspelled.");
      Form_Main->Timer1->Enabled = FALSE;
      Form_Main->ProgressBar1->Position = 100;
      Synchronize((TThreadMethod)&button_end);
      if (FileExists(dest))
         DeleteFile(dest);
      if (FileExists(source))
         DeleteFile(source);
      return;
    }

   free(password);
   if (FileExists(logs))
           Form_Main->RichEdit1->Lines->LoadFromFile(logs);

   Synchronize((TThreadMethod)&progress);
   Synchronize((TThreadMethod)&button_end);
}




//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Text_DecryptClick(TObject *Sender)
{
if (strcmp(RichEdit_Text->Text.c_str(),"") == 0)
   {
    ListBox1->Items->Add("No data to decrypt.");
    ListBox1->Items->Add("Please type something in the Text Editor first");
    return;
   }

Form_Main->Edit_Text_Verif->Visible = FALSE;
Form_Main->Label_Text_Verif->Visible = FALSE;
Form_Main->Button_Text_Crypt_Action->Visible = FALSE;
Form_Main->Button_Text_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Text_Decrypt_Action->Enabled = TRUE;
Form_Main->Button_Text_Decrypt_Action->Visible = TRUE;
Form_Main->Panel_Text->Visible = TRUE;
Form_Main->Panel_Text->BringToFront();
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Button_Text_Decrypt_ActionClick(
      TObject *Sender)
{
char *temp_bugs_clear="temp_edit_bugs1";
char *temp_bugs_crypted="temp_edit_bugs2";
SESSION_SECONDS = 0;
SESSION_MINUTES = 0;
SESSION_HOURS = 0;

varinit->PROGRESS = 0;

Form_Main->ListBox1->Items->Add("Decrypting Text Editor in progress.");
Form_Main->ListBox1->Items->Add("");
Form_Main->ListBox1->Items->Add("Saving Texteditor data into 'temp_edit_bugs' file");
if (FileExists(temp_bugs_clear))
   {
    Form_Main->ListBox1->Items->Add("Removing previous temp files.");
    DeleteFile(temp_bugs_clear);
    DeleteFile(temp_bugs_crypted);
   }

RichEdit_Text->Lines->SaveToFile(temp_bugs_clear);
Form_Main->RichEdit1->Clear();

thtext_decrypt *test = new thtext_decrypt;
test->Resume();

Form_Main->Button_Crypt_Action->Enabled = FALSE;
Form_Main->Button_Decrypt_Action->Enabled = FALSE;
Form_Main->Button_Hide_Action->Enabled = FALSE;
Form_Main->Button_Keyfile_Action->Enabled = FALSE;
Form_Main->Button_Text_Decrypt_Action->Enabled = FALSE;

}

void __fastcall thtext_decrypt::progress(void)

{
  varinit->PROGRESS=100;
  Form_Main->ProgressBar1->Position = 100;
}

void __fastcall thtext_decrypt::button_end(void)

{
   Form_Main->Button_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Hide_Action->Enabled = TRUE;
   Form_Main->Button_Keyfile_Action->Enabled = TRUE;
   Form_Main->Button_Text_Stop->Enabled = TRUE;
   Form_Main->Button_Text_Crypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt_Action->Enabled = TRUE;
   Form_Main->Button_Text_Crypt->Enabled = TRUE;
   Form_Main->Button_Text_Decrypt->Enabled = TRUE;
}

__fastcall thtext_decrypt::thtext_decrypt() : TThread(True)
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

void __fastcall thtext_decrypt::Execute()
{
int power, bc, bs, mode, method, round, action, keylength, random,
    keytype, i;
char buf[200]="";
char *source="temp_edit_bugs1";
char *dest="temp_edit_bugs2";

   unsigned char *password;
   char logs[MAXPATH]="";

strcpy(logs,PATH_LOGS);
strcat(logs,"\\editor_decrypt.log");

Form_Main->ListBox1->Clear();

bc = atoi(Form_Main->Edit_Bc->Text.c_str());
bs = atoi(Form_Main->Edit_Bs->Text.c_str());
round = atoi(Form_Main->Edit_Round->Text.c_str());
keylength = atoi(Form_Main->Label_Keylength->Caption.c_str());



if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Quiet") == 0)
        mode = 0;
   else
        {
        if (strcmp(Form_Main->Combo_Logs->Text.c_str(),"Verbose") == 0)
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


 /*
 *  Forcing to mode = ASCII and method = MEMORY
 */
method = 1;
action = 3;

if (strcmp(Form_Main->Combo_Random->Text.c_str(),"ISAAC") == 0)
        random = 1;
   else
        random = 0;

if (strcmp(Form_Main->Combo_Keytype->Text.c_str(),"Password") == 0)
        keytype = 0;
   else
        keytype = 1;

char* keyfile = StrNew(Form_Main->Edit_Text_Keyfile->Text.c_str());


if (1 == keytype)
   {
    if (strcmp(Form_Main->Edit_Text_Keyfile->Text.c_str(),"") == 0)
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please select a KEY FILE.");
   Synchronize((TThreadMethod)&button_end);
   if (FileExists(dest))
       DeleteFile(dest);
   if (FileExists(source))
       DeleteFile(source);
   return;
   }


 if (!FileExists(Form_Main->Edit_Text_Keyfile->Text.c_str()))
      {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("KEY FILE doesn't exist.");
   Synchronize((TThreadMethod)&button_end);
   if (FileExists(dest))
       DeleteFile(dest);
   if (FileExists(source))
       DeleteFile(source);
   return;
   }

  }

if ((0 == keytype) && (strcmp(Form_Main->Edit_Text_Password->Text.c_str(),"") == 0))
   {
   Form_Main->ListBox1->Items->Add("ERROR.");
   Form_Main->ListBox1->Items->Add("Please enter a password");
   Synchronize((TThreadMethod)&button_end);
   if (FileExists(dest))
       DeleteFile(dest);
   if (FileExists(source))
       DeleteFile(source);
   return;
   }

if (Form_Main->Edit_Text_Password->Text.Length() < BCRYPT_MIN_PASSWORD)
   {
    Form_Main->ListBox1->Items->Add("ERROR.");
    Form_Main->ListBox1->Items->Add("Password too short");
    Synchronize((TThreadMethod)&button_end);
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

Form_Main->ListBox1->Items->Add("DECrypting in Progress...");

if (FileExists(logs))
      DeleteFile(logs);

Form_Main->ListBox1->Items->Add("Old logs deleted.");



if (
   (keytype == 1) || (strcmp(Form_Main->Edit_Text_Password->Text.c_str(),"") != 0)
   )
   {

    Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Working...");
    Form_Main->ListBox1->Items->Add("");

    Form_Main->ListBox1->Refresh();

    Form_Main->Timer1->Enabled = TRUE;

    binit(keylength, random,logs, 1,varinit);

    password = (unsigned char *)malloc(varinit->NB_CHAR);

        Form_Main->ListBox1->Items->Add("");
    Form_Main->ListBox1->Items->Add("Initialisation Done");
    Form_Main->ListBox1->Items->Add("Please Wait...");
    varinit->MISC = 0;

    if (Form_Main->Check_Round->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_ROUND;
         Form_Main->ListBox1->Items->Add("Dynamic Round");
        }

    if (Form_Main->Check_Shuffle->Checked == TRUE)
        {
         varinit->MISC ^= BMASK_SHUFFLE;
         Form_Main->ListBox1->Items->Add("Dynamic Block Shuffle");
        }

    if (Form_Main->Check_Swap->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_SWAP;
      Form_Main->ListBox1->Items->Add("Dynamic Modulo Swap");
     }

    if (Form_Main->Check_Buffer->Checked == TRUE)
     {
      varinit->MISC ^= BMASK_BUFFER;
      Form_Main->ListBox1->Items->Add("Dynamic Key Buffer");
     }

    varinit->KEY_BUFFER = atoi(Form_Main->Edit_Buffer->Text.c_str());



    if (Form_Main->Edit_Text_Password->Text.Length() > varinit->NB_CHAR)
       {
        i = varinit->NB_CHAR;
        Form_Main->ListBox1->Items->Add("Password length reduced.");
       }
    else
        i = Form_Main->Edit_Text_Password->Text.Length();

    strncpy(password, Form_Main->Edit_Text_Password->Text.c_str(), i);

    if (bfile (action,source,dest, Form_Main->Edit_Text_Keyfile->Text.c_str(),password, i,
          power, round, bc, bs, method, mode, varinit) == 0)
    {
     Form_Main->Timer1->Enabled = FALSE;
     Form_Main->ListBox1->Items->Add("");
     Form_Main->ListBox1->Items->Add("ERROR.");
     Form_Main->ListBox1->Items->Add("Please Look at the ADVANCED LOGS");
     }
     else
     {

     if (FileExists(source))
       DeleteFile(source);

       if (FileExists(dest))
           {
            Form_Main->RichEdit_Text->Lines->LoadFromFile(dest);
            DeleteFile(dest);
           }
        else
           {
            Form_Main->ListBox1->Items->Add("ERROR.");
            Form_Main->ListBox1->Items->Add("Cannot find tempory crypted file.");
           }
           
      Form_Main->Timer1->Enabled = FALSE;
      Form_Main->ListBox1->Items->Add("");
      Form_Main->ListBox1->Items->Add("Time To Complete: ");
      Form_Main->ListBox1->Items->Add(Form_Main->Label_Logs_Time->Caption);
      Form_Main->ListBox1->Items->Add("Done !");
      Form_Main->ListBox1->Items->Add("");
      Form_Main->Edit_Text_Password->Clear();
      Form_Main->Panel_Text->Visible = FALSE;
     }

     }
   else
   {
    Form_Main->ListBox1->Items->Add("ERROR.");
    Form_Main->ListBox1->Items->Add("Password Misspelled.");
    Form_Main->Timer1->Enabled = FALSE;
    Synchronize((TThreadMethod)&button_end);
   if (FileExists(dest))
       DeleteFile(dest);
   if (FileExists(source))
       DeleteFile(source);
    return;
   }

   free(password);

if (FileExists(logs))
   Form_Main->RichEdit1->Lines->LoadFromFile(logs);

   Synchronize((TThreadMethod)&progress);
   Synchronize((TThreadMethod)&button_end);
}


//---------------------------------------------------------------------------

void __fastcall TForm_Main::TrackBar1Change(TObject *Sender)
{
int i;
char string[12];
i = pow(2,TrackBar1->Position);
itoa(i,string,10);
Label_Keylength->Caption = string;
TrackBar1->SelEnd = TrackBar1->Position;


BCRYPT_MIN_PASSWORD = (i / 8) / 2;
BCRYPT_MAX_PASSWORD = (i / 8);
Form_Main->Label_Keyinfo->Caption = string;

if (Form_Main->PageControl1->ActivePage->TabIndex == 2)
{
Form_Main->Label_Min_Password->Caption = "8";
Form_Main->Label_Max_Password->Caption = "16";
}
else
{
itoa(BCRYPT_MIN_PASSWORD,string,10);
Form_Main->Label_Min_Password->Caption = string;
itoa(BCRYPT_MAX_PASSWORD,string,10);
Form_Main->Label_Max_Password->Caption = string;
}

if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }
}

//---------------------------------------------------------------------------



void __fastcall TForm_Main::Button15Click(TObject *Sender)
{
int i, mode, max, step, exit;


if (GroupBox1->Visible == FALSE)
{
srand(time(NULL)+ clock());
mode = rand()%2;

switch(mode)
      {
      case 0: i=-360;
              max=0;
              step=15;
              break;

      default: i=360;
               max=0;
               step=-15;
               break;
      }

      GroupBox1->Top = i;
      GroupBox1->Visible=True;
      GroupBox1->BringToFront();

      exit=0;

      do
      {

       GroupBox1->Top = i;
       GroupBox8->Refresh();
       GroupBox1->Refresh();
       Sleep(1);
       i=i+step;

       if (0 < step)
          {
          if (i > max) exit=1;
          }
       else
          {
          if (i < max) exit=1;
          }

      } while (FALSE == exit);
}
GroupBox8->Visible=False;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Combo_PriorityChange(TObject *Sender)
{
BCRYPT_PRIORITY = Combo_Priority->ItemIndex;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Choice_Info()
{
char string[20];
/*
 * CRYPT
 */
if (Form_Main->PageControl1->ActivePage->TabIndex == 0)
{

Form_Main->Label_Action->Caption = "CRYPT";

if (0 == Form_Main->Combo_Power->ItemIndex)
        Form_Main->Speed_Power->Caption = "Seed";
else
  {
    if (1 == Form_Main->Combo_Power->ItemIndex)
          Form_Main->Speed_Power->Caption = "Rnd Seed";
    else
       {
       if (2 == Form_Main->Combo_Power->ItemIndex)
           Form_Main->Speed_Power->Caption = "Shuffle";
       else
          {
           if (3 == Form_Main->Combo_Power->ItemIndex)
              Form_Main->Speed_Power->Caption = "Shuffle + Seed";
           else
             {
              if (4 == Form_Main->Combo_Power->ItemIndex)
                 Form_Main->Speed_Power->Caption = "Shuffle + Rnd Seed";
             }
          }
       }
  }

itoa(BCRYPT_MIN_PASSWORD,string,10);
Form_Main->Label_Min_Password->Caption = string;
itoa(BCRYPT_MAX_PASSWORD,string,10);
Form_Main->Label_Max_Password->Caption = string;

if (0 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Quiet";

if (1 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Verbose";

if (2 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Debug";

if (0 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="Binary";

if (1 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="ASCII";

if (0 == Form_Main->Combo_Keytype->ItemIndex)
        Form_Main->Speed_Keytype->Caption="Password";
else
        Form_Main->Speed_Keytype->Caption="Keyfile";

Form_Main->Label_Log_Keytype->Visible = TRUE;
Form_Main->Speed_Keytype->Visible = TRUE;

Form_Main->Label_Action_Tittle->Visible = TRUE;
Form_Main->Label_Power_Tittle->Visible = TRUE;
Form_Main->Label_Min_Password_Tittle->Visible = TRUE;
Form_Main->Label_Max_Password_Tittle->Visible = TRUE;
Form_Main->Label_Logs_Tittle->Visible = TRUE;
Form_Main->Label_Keyinfo_Tittle->Visible = TRUE;

Form_Main->Label_Keyinfo->Visible = TRUE;
Form_Main->Label_Action->Visible = TRUE;
Form_Main->Speed_Power->Visible = TRUE;
Form_Main->Label_Bssl_Tittle->Visible = TRUE;
Form_Main->Label_Cipher_Tittle->Visible = TRUE;
Form_Main->Label_Min_Password->Visible = TRUE;
Form_Main->Label_Max_Password->Visible = TRUE;
Form_Main->Speed_Logs->Visible = TRUE;
Form_Main->Speed_Bssl->Visible = TRUE;
Form_Main->Speed_Cipher->Visible = TRUE;
}

/*
 * DECRYPT
 */
if (Form_Main->PageControl1->ActivePage->TabIndex == 1)
{
Form_Main->Label_Action->Caption = "DECRYPT";
if (0 == Form_Main->Combo_Power->ItemIndex)
        Form_Main->Speed_Power->Caption = "Seed";
if (1 == Form_Main->Combo_Power->ItemIndex)
        Form_Main->Speed_Power->Caption = "Rnd Seed";
if (2 == Form_Main->Combo_Power->ItemIndex)
        Form_Main->Speed_Power->Caption = "Shuffle";
if (3 == Form_Main->Combo_Power->ItemIndex)
        Form_Main->Speed_Power->Caption = "Shuffle + Seed";
if (4 == Form_Main->Combo_Power->ItemIndex)
        Form_Main->Speed_Power->Caption = "Shuffle + Rnd Seed";

itoa(BCRYPT_MIN_PASSWORD,string,10);
Form_Main->Label_Min_Password->Caption = string;
itoa(BCRYPT_MAX_PASSWORD,string,10);
Form_Main->Label_Max_Password->Caption = string;

if (0 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Quiet";
else
   {
        if (1 == Form_Main->Combo_Logs->ItemIndex)
            Form_Main->Speed_Logs->Caption="Verbose";
       else
            Form_Main->Speed_Logs->Caption="Debug";
   }

if (0 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="Binary";

if (1 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="ASCII";

if (0 == Form_Main->Combo_Keytype->ItemIndex)
        Form_Main->Speed_Keytype->Caption="Password";
else
        Form_Main->Speed_Keytype->Caption="Keyfile";

Form_Main->Label_Log_Keytype->Visible = TRUE;
Form_Main->Speed_Keytype->Visible = TRUE;

Form_Main->Label_Action_Tittle->Visible = TRUE;
Form_Main->Label_Power_Tittle->Visible = TRUE;
Form_Main->Label_Bssl_Tittle->Visible = TRUE;
Form_Main->Label_Cipher_Tittle->Visible = TRUE;
Form_Main->Label_Min_Password_Tittle->Visible = TRUE;
Form_Main->Label_Max_Password_Tittle->Visible = TRUE;
Form_Main->Label_Logs_Tittle->Visible = TRUE;
Form_Main->Label_Keyinfo_Tittle->Visible = TRUE;

Form_Main->Label_Keyinfo->Visible = TRUE;
Form_Main->Label_Action->Visible = TRUE;
Form_Main->Speed_Power->Visible = TRUE;
Form_Main->Label_Min_Password->Visible = TRUE;
Form_Main->Label_Max_Password->Visible = TRUE;
Form_Main->Speed_Logs->Visible = TRUE;
Form_Main->Speed_Bssl->Visible = TRUE;
Form_Main->Speed_Cipher->Visible = TRUE;

}

/*
 * Generate KEYFILE
 */
if (Form_Main->PageControl1->ActivePage->TabIndex == 2)
{
Form_Main->Label_Action->Caption = "Generate KEYFILE";

Form_Main->Label_Min_Password->Caption = "8";
Form_Main->Label_Max_Password->Caption = "16";

if (0 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Quiet";

if (1 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Verbose";

if (2 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Debug";


if (0 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="Binary";

if (1 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="ASCII";

Form_Main->Label_Log_Keytype->Visible = FALSE;
Form_Main->Speed_Keytype->Visible = FALSE;

Form_Main->Label_Action_Tittle->Visible = TRUE;
Form_Main->Label_Power_Tittle->Visible = FALSE;
Form_Main->Label_Bssl_Tittle->Visible = FALSE;
Form_Main->Label_Cipher_Tittle->Visible = FALSE;
Form_Main->Label_Min_Password_Tittle->Visible = TRUE;
Form_Main->Label_Max_Password_Tittle->Visible = TRUE;
Form_Main->Label_Logs_Tittle->Visible = TRUE;
Form_Main->Label_Keyinfo_Tittle->Visible = TRUE;

Form_Main->Label_Keyinfo->Visible = TRUE;
Form_Main->Label_Action->Visible = TRUE;
Form_Main->Speed_Power->Visible = FALSE;
Form_Main->Label_Min_Password->Visible = TRUE;
Form_Main->Label_Max_Password->Visible = TRUE;
Form_Main->Speed_Logs->Visible = TRUE;
Form_Main->Speed_Bssl->Visible = FALSE;
Form_Main->Speed_Cipher->Visible = FALSE;

}

if (Form_Main->PageControl1->ActivePage->TabIndex == 3)
{
Form_Main->Label_Action->Caption = "HIDE/EXTRACT";

if (0 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Quiet";

if (1 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Verbose";

if (2 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Debug";

if (0 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="Binary";

if (1 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="ASCII";

Form_Main->Label_Log_Keytype->Visible = FALSE;
Form_Main->Speed_Keytype->Visible = FALSE;

Form_Main->Label_Action_Tittle->Visible = TRUE;
Form_Main->Label_Power_Tittle->Visible = FALSE;
Form_Main->Label_Bssl_Tittle->Visible = FALSE;
Form_Main->Label_Cipher_Tittle->Visible = FALSE;
Form_Main->Label_Min_Password_Tittle->Visible = FALSE;
Form_Main->Label_Max_Password_Tittle->Visible = FALSE;
Form_Main->Label_Logs_Tittle->Visible = TRUE;
Form_Main->Label_Keyinfo_Tittle->Visible = FALSE;

Form_Main->Label_Keyinfo->Visible = FALSE;
Form_Main->Label_Action->Visible = TRUE;
Form_Main->Speed_Power->Visible = FALSE;
Form_Main->Label_Min_Password->Visible = FALSE;
Form_Main->Label_Max_Password->Visible = FALSE;
Form_Main->Speed_Logs->Visible = TRUE;
Form_Main->Speed_Bssl->Visible = FALSE;
Form_Main->Speed_Cipher->Visible = FALSE;

}

if (Form_Main->PageControl1->ActivePage->TabIndex == 4)
{
Form_Main->Label_Action->Caption = "View FILE";

if (0 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption = "Quiet";
else
   {
        if (1 == Form_Main->Combo_Logs->ItemIndex)
                Form_Main->Speed_Logs->Caption="Verbose";
        else
                Form_Main->Speed_Logs->Caption="Debug";
    }

if (0 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="Binary";

if (1 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="ASCII";

Form_Main->Label_Log_Keytype->Visible = FALSE;
Form_Main->Speed_Keytype->Visible = FALSE;

Form_Main->Label_Action_Tittle->Visible = TRUE;
Form_Main->Label_Power_Tittle->Visible = FALSE;
Form_Main->Label_Bssl_Tittle->Visible = FALSE;
Form_Main->Label_Cipher_Tittle->Visible = FALSE;
Form_Main->Label_Min_Password_Tittle->Visible = FALSE;
Form_Main->Label_Max_Password_Tittle->Visible = FALSE;
Form_Main->Label_Logs_Tittle->Visible = TRUE;
Form_Main->Label_Keyinfo_Tittle->Visible = FALSE;

Form_Main->Label_Keyinfo->Visible = FALSE;
Form_Main->Label_Action->Visible = TRUE;
Form_Main->Speed_Power->Visible = FALSE;
Form_Main->Label_Min_Password->Visible = FALSE;
Form_Main->Label_Max_Password->Visible = FALSE;
Form_Main->Speed_Logs->Visible = TRUE;
Form_Main->Speed_Bssl->Visible = FALSE;
Form_Main->Speed_Cipher->Visible = FALSE;
}

if (Form_Main->PageControl1->ActivePage->TabIndex == 5)
{
Form_Main->Label_Action->Caption = "TEXT EDITOR";

if (0 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Quiet";

if (1 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Verbose";

if (2 == Form_Main->Combo_Logs->ItemIndex)
        Form_Main->Speed_Logs->Caption="Debug";

if (0 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="Binary";

if (1 == Form_Main->Combo_Mode->ItemIndex)
        Form_Main->Speed_Cipher->Caption="ASCII";

if (0 == Form_Main->Combo_Keytype->ItemIndex)
        Form_Main->Speed_Keytype->Caption="Password";
else
        Form_Main->Speed_Keytype->Caption="Keyfile";

Form_Main->Label_Log_Keytype->Visible = TRUE;
Form_Main->Speed_Keytype->Visible = TRUE;
        
Form_Main->Label_Action_Tittle->Visible = TRUE;
Form_Main->Label_Power_Tittle->Visible = TRUE;
Form_Main->Label_Bssl_Tittle->Visible = TRUE;
Form_Main->Label_Cipher_Tittle->Visible = TRUE;
Form_Main->Label_Min_Password_Tittle->Visible = TRUE;
Form_Main->Label_Max_Password_Tittle->Visible = TRUE;
Form_Main->Label_Logs_Tittle->Visible = TRUE;
Form_Main->Label_Keyinfo_Tittle->Visible = TRUE;

Form_Main->Label_Keyinfo->Visible = TRUE;
Form_Main->Label_Action->Visible = TRUE;
Form_Main->Speed_Power->Visible = TRUE;
Form_Main->Label_Min_Password->Visible = TRUE;
Form_Main->Label_Max_Password->Visible = TRUE;
Form_Main->Speed_Logs->Visible = TRUE;
Form_Main->Speed_Bssl->Visible = TRUE;
Form_Main->Speed_Cipher->Visible = TRUE;

}




}
//---------------------------------------------------------------------------


void __fastcall TForm_Main::PageControl1Change(TObject *Sender)
{
Form_Main->Choice_Info();
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Combo_PowerChange(TObject *Sender)
{
Form_Main->Choice_Info();
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }

 CYCLE_POWER = Form_Main->Combo_Power->ItemIndex;

}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Combo_LogsChange(TObject *Sender)
{
Form_Main->Choice_Info();
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::BitBtn4Click(TObject *Sender)
{
int i, mode, max, step, exit;


if (GroupBox8->Visible == FALSE)
{
srand(time(NULL)+ clock());
mode = rand()%2;

switch(mode)
      {
      case 0: i=-360;
              max=0;
              step=15;
              break;

      default: i=360;
               max=0;
               step=-15;
               break;
      }

      GroupBox8->Top = i;
      GroupBox8->Visible=True;
      GroupBox8->BringToFront();
      
      exit=0;

      do
      {

       GroupBox8->Top = i;
       GroupBox1->Refresh();
       GroupBox8->Refresh();
       Sleep(1);
       i=i+step;

       if (0 < step)
          {
          if (i > max) exit=1;
          }
       else
          {
          if (i < max) exit=1;
          }

      } while (FALSE == exit);

GroupBox1->Visible=False;
}


/*
 * OLD METHOD which also handle RIGHT AND LEFT
 
int i, top,left,mode, move, max, step, exit;

for (i=192; i <480; i = i + 5)
     {
     GroupBox7->Top = i;
     GroupBox1->Refresh();
     GroupBox4->Refresh();
     Sleep(1);
     }


if (GroupBox2->Visible == FALSE)
{
srand(time(NULL)+ clock());
mode = rand()%3;

top=8;
left=328;

GroupBox2->Top = top;
GroupBox2->Left = left;
GroupBox2->Visible=True;

switch(mode)
      {
      case 0: move=1;
              i=top;
              max=168;
              step=5;
              break;

      case 1: move=1;
              i=top;
              max=-144;
              step=-5;
              break;

      default: move=2;
               i=left;
               max=618;
               step=5;
               break;
      }

      exit=0;

      do
      {
       if (1 == move)
               GroupBox5->Top = i;
       else
               GroupBox5->Left = i;

       i=i+step;
       GroupBox2->Refresh();
       Sleep(1);

       if (0 < step)
          {
          if (i > max) exit=1;
          }
       else
          {
          if (i < max) exit=1;
          }

      } while (FALSE == exit);

GroupBox5->Visible=False;
GroupBox2->BringToFront();
}
*/

}
//---------------------------------------------------------------------------


char * __fastcall GetRegistryValue(char *KeyName)
{
 int i;
  TRegistry *Registry = new TRegistry;
  try
  {
    Registry->RootKey = HKEY_CLASSES_ROOT;
    // False because we do not want to create it if it doesn’t exist

    if (Registry->OpenKey(KeyName,false))
       {

        char *Name = StrNew(Registry->ReadString("").c_str());
        Registry->CloseKey();
        return (Name);
       }
     else
      {
        return ("");
      }
  }
  __finally
  {
    delete Registry;
    return ("");
  }


}



void __fastcall OpenWebPage(char *string)
{
char temp[MAX_PATH];

char *cmd = StrNew(GetRegistryValue("htmlfile\\shell\\open\\command"));
strcpy(temp,cmd);
strcat(temp," ");
strcat(temp,string);
strcat(temp,"\0");



  if (strcmp(temp,"") !=  0)
     {
      system(temp);

     }

     free(temp);
     free(cmd);

}




void __fastcall TForm_Main::FormClose(TObject *Sender,
      TCloseAction &Action)
{
try
{
 fclose(BCRYPTLOG);
 free(varinit);
}
__except(EXCEPTION_EXECUTE_HANDLER)
{
 Application->MessageBox("Error while trying to clean up the memory", "Error Message", MB_OK);
}

}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Combo_BsslChange(TObject *Sender)
{
CYCLE_BSSL_CONTROL = 1;
Choice_Bssl();
CYCLE_BSSL = Form_Main->Combo_Bssl->ItemIndex;
CYCLE_BSSL_CONTROL = 0;
}
//---------------------------------------------------------------------------
void __fastcall TForm_Main::Choice_Bssl()
{
int power,i,j,round,bc,bs;
char string[20];

power = bssl(Form_Main->Combo_Bssl->ItemIndex,&round, &bc, &bs, varinit, 0);

if (power > 0)
 {
  Form_Main->Combo_Power->ItemIndex = power;
  if (BMASK_ROUND == (varinit->MISC & BMASK_ROUND))
   Form_Main->Check_Round->Checked = TRUE;
  else
   Form_Main->Check_Round->Checked = FALSE;

  if (BMASK_SHUFFLE == (varinit->MISC & BMASK_SHUFFLE))
   Form_Main->Check_Shuffle->Checked = TRUE;
  else
   Form_Main->Check_Shuffle->Checked = FALSE;

  if (BMASK_SWAP == (varinit->MISC & BMASK_SWAP))
   Form_Main->Check_Swap->Checked = TRUE;
  else
   Form_Main->Check_Swap->Checked = FALSE;

  if (BMASK_BUFFER == (varinit->MISC & BMASK_BUFFER))
   Form_Main->Check_Buffer->Checked = TRUE;
  else
   Form_Main->Check_Buffer->Checked = FALSE;

  itoa(varinit->KEY_BUFFER,string,10);
  Form_Main->Edit_Buffer->Text = string;
  itoa(round,string,10);
  Form_Main->Edit_Round->Text = string;
  itoa(bc,string,10);
  Form_Main->Edit_Bc->Text = string;
  itoa(bs,string,10);
  Form_Main->Edit_Bs->Text = string;

  i = varinit->KEYLENGTH;
  j = 0;
  while (i > 0)
   {
    j++;
    i = i/2;
   }
  Form_Main->TrackBar1->Position = j-1;
  Choice_Info();

   if (1 == Form_Main->Combo_Bssl->ItemIndex)
    Form_Main->Speed_Bssl->Caption = "Very Low Security";
   else
    if (2 == Form_Main->Combo_Bssl->ItemIndex)
     Form_Main->Speed_Bssl->Caption = "Low Security";
    else
     if (3 == Form_Main->Combo_Bssl->ItemIndex)
      Form_Main->Speed_Bssl->Caption = "Medium Security";
     else
      if (4 == Form_Main->Combo_Bssl->ItemIndex)
       Form_Main->Speed_Bssl->Caption = "High Security";
      else
       if (5 == Form_Main->Combo_Bssl->ItemIndex)
        Form_Main->Speed_Bssl->Caption = "Very High Security";

 }
else
  if (0 == Form_Main->Combo_Bssl->ItemIndex)
   Form_Main->Speed_Bssl->Caption = "Custom Security";
}


void __fastcall TForm_Main::Speed_BsslClick(TObject *Sender)
{

CYCLE_BSSL = (CYCLE_BSSL + 1)%CYCLE_BSSL_MAX;
Form_Main->Combo_Bssl->ItemIndex = CYCLE_BSSL;
CYCLE_BSSL_CONTROL = 1;
Form_Main->Choice_Bssl();
CYCLE_BSSL_CONTROL = 0;

}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Edit_BcChange(TObject *Sender)
{
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Edit_BsChange(TObject *Sender)
{
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Edit_RoundChange(TObject *Sender)
{
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Edit_BufferChange(TObject *Sender)
{
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Check_ShuffleClick(TObject *Sender)
{
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Check_RoundClick(TObject *Sender)
{
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Check_BufferClick(TObject *Sender)
{
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Check_SwapClick(TObject *Sender)
{
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Speed_PowerClick(TObject *Sender)
{
if (0 == CYCLE_BSSL_CONTROL)
 {
  Form_Main->Combo_Bssl->ItemIndex = 0;
  Form_Main->Choice_Bssl();
  CYCLE_BSSL = 0;
 }

CYCLE_POWER = (CYCLE_POWER + 1) %CYCLE_POWER_MAX;
Form_Main->Combo_Power->ItemIndex = CYCLE_POWER;
Form_Main->Choice_Info();
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Speed_CipherClick(TObject *Sender)
{
CYCLE_CIPHER = (CYCLE_CIPHER + 1) %CYCLE_CIPHER_MAX;

Form_Main->Combo_Mode->ItemIndex = CYCLE_CIPHER;

if (Form_Main->Combo_Mode->ItemIndex == 1)
    Form_Main->Combo_Method->ItemIndex = 0;

CYCLE_BSSL_CONTROL = 1;
Form_Main->Choice_Info();
CYCLE_BSSL_CONTROL = 0;
}
//---------------------------------------------------------------------------

void __fastcall TForm_Main::Speed_LogsClick(TObject *Sender)
{
CYCLE_LOGS = (CYCLE_LOGS + 1) %CYCLE_LOGS_MAX;

Form_Main->Combo_Logs->ItemIndex = CYCLE_LOGS;

CYCLE_BSSL_CONTROL = 1;
Form_Main->Choice_Info();
CYCLE_BSSL_CONTROL = 0;
}
//---------------------------------------------------------------------------


void __fastcall TForm_Main::Speed_KeytypeClick(TObject *Sender)
{
CYCLE_KEY = (CYCLE_KEY + 1) %CYCLE_KEY_MAX;

Form_Main->Combo_Keytype->ItemIndex = CYCLE_KEY;

CYCLE_BSSL_CONTROL = 1;
Form_Main->Choice_Info();
CYCLE_BSSL_CONTROL = 0;

if (0 == CYCLE_KEY)
{
      Edit_Crypt_Keyfile->Visible = FALSE;
        Button_Crypt_Keyfile->Visible = FALSE;
        Label_Crypt_Keyfile->Visible = FALSE;
        Edit_Crypt_Password->Visible = TRUE;
        Edit_Crypt_Verif->Visible = TRUE;
        Label_Crypt_Password->Visible = TRUE;
        Label_Crypt_Verif->Visible = TRUE;


        Edit_Decrypt_Keyfile->Visible = FALSE;
        Button_Decrypt_Keyfile->Visible = FALSE;
        Label_Decrypt_Keyfile->Visible = FALSE;
        Edit_Decrypt_Password->Visible = TRUE;
        Label_Decrypt_Password->Visible = TRUE;

        Edit_Text_Keyfile->Visible = FALSE;
        Button_Text_Keyfile->Visible = FALSE;
        Label_Text_Keyfile->Visible = FALSE;
        Edit_Text_Password->Visible = TRUE;
        Edit_Text_Verif->Visible = TRUE;
        Label_Text_Password->Visible = TRUE;
        Label_Text_Verif->Visible = TRUE;
}
else
{
        Edit_Crypt_Keyfile->Visible = TRUE;
        Button_Crypt_Keyfile->Visible = TRUE;
        Label_Crypt_Keyfile->Visible = TRUE;
        Edit_Crypt_Password->Visible = FALSE;
        Edit_Crypt_Verif->Visible = FALSE;
        Label_Crypt_Password->Visible = FALSE;
        Label_Crypt_Verif->Visible = FALSE;

        Edit_Decrypt_Keyfile->Visible = TRUE;
        Button_Decrypt_Keyfile->Visible = TRUE;
        Label_Decrypt_Keyfile->Visible = TRUE;
        Edit_Decrypt_Password->Visible = FALSE;
        Label_Decrypt_Password->Visible = FALSE;

        Edit_Text_Keyfile->Visible = TRUE;
        Button_Text_Keyfile->Visible = TRUE;
        Label_Text_Keyfile->Visible = TRUE;
        Edit_Text_Password->Visible = FALSE;
        Edit_Text_Verif->Visible = FALSE;
        Label_Text_Password->Visible = FALSE;
        Label_Text_Verif->Visible = FALSE;
}

}
//---------------------------------------------------------------------------

