//---------------------------------------------------------------------------
#ifndef bcryptH
#define bcryptH
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include <Dialogs.hpp>
#include <ExtCtrls.hpp>
#include <ComCtrls.hpp>
#include <Mask.hpp>
#include <Buttons.hpp>
#include <NMsmtp.hpp>
#include <Psock.hpp>
#include <jpeg.hpp>
//#USEUNIT("func_bcrypt.cpp")
//---------------------------------------------------------------------------
class TForm_Main : public TForm
{
__published:	// IDE-managed Components
        TOpenDialog *OpenDialog1;
        TGroupBox *GroupBox1;
        TPageControl *PageControl1;
        TTabSheet *TabSheet1;
        TEdit *Edit_Crypt_Source;
        TEdit *Edit_Crypt_Dest;
        TEdit *Edit_Crypt_Keyfile;
        TEdit *Edit_Crypt_Password;
        TButton *Button_Crypt_Source;
        TButton *Button_Crypt_Dest;
        TButton *Button_Crypt_Keyfile;
        TEdit *Edit_Crypt_Verif;
        TButton *Button_Crypt_Action;
        TTabSheet *TabSheet2;
        TEdit *Edit_Decrypt_Source;
        TEdit *Edit_Decrypt_Dest;
        TEdit *Edit_Decrypt_Keyfile;
        TEdit *Edit_Decrypt_Password;
        TButton *Button_Decrypt_Source;
        TButton *Button_Decrypt_Dest;
        TButton *Button_Decrypt_Keyfile;
        TButton *Button_Decrypt_Action;
        TLabel *Label_Crypt_Source;
        TLabel *Label_Crypt_Dest;
        TLabel *Label_Crypt_Keyfile;
        TLabel *Label_Crypt_Password;
        TLabel *Label_Crypt_Verif;
        TGroupBox *GroupBox4;
        TListBox *ListBox1;
        TLabel *Label_Decrypt_Source;
        TLabel *Label_Decrypt_Dest;
        TLabel *Label_Decrypt_Keyfile;
        TLabel *Label_Decrypt_Password;
        TTabSheet *TabSheet3;
        TButton *Button3;
        TButton *Button4;
        TRichEdit *RichEdit1;
        TPanel *Panel1;
        TButton *Button5;
        TRadioButton *Radio_Keyfile_Random;
        TRadioButton *Radio_Keyfile_Password;
        TEdit *Edit_Keyfile_Password;
        TButton *Button_Keyfile_Action;
        TLabel *Label15;
        TEdit *Edit_Keyfile_File;
        TTabSheet *TabSheet4;
        TPanel *Panel3;
        TPanel *Panel4;
        TRadioButton *Radio_Hide_Hide;
        TRadioButton *Radio_Hide_Extract;
        TRadioButton *Radio_Hide_End;
        TRadioButton *Radio_Hide_Begining;
        TLabel *Label16;
        TEdit *Edit_Hide_Source;
        TButton *Button7;
        TLabel *Label17;
        TEdit *Edit_Hide_Dest;
        TButton *Button8;
        TButton *Button_Hide_Action;
        TTabSheet *TabSheet5;
        TBitBtn *BitBtn1;
        TBitBtn *BitBtn2;
        TPanel *Panel5;
        TTabSheet *TabSheet6;
        TPanel *Panel6;
        TSpeedButton *SpeedButton1;
        TSpeedButton *SpeedButton2;
        TSpeedButton *SpeedButton3;
        TImage *Image1;
        TRichEdit *RichEdit2;
        TRichEdit *RichEdit_Text;
        TGroupBox *GroupBox6;
        TButton *Button6;
        TPanel *Panel7;
        TImage *Image2;
        TPanel *Panel8;
        TLabel *Label19;
        TLabel *Label20;
        TLabel *Label21;
        TLabel *Label22;
        TRichEdit *RichEdit4;
        TButton *Button9;
        TButton *Button10;
        TButton *Button11;
        TButton *Button12;
        TTimer *Timer1;
        TBitBtn *Button_Crypt_Stop;
        TBitBtn *Button_Decrypt_Stop;
        TBitBtn *Button_Keyfile_Stop;
        TBitBtn *Button_Hide_Stop;
        TPanel *Panel10;
        TButton *Button_Text_Crypt;
        TButton *Button_Text_Decrypt;
        TPanel *Panel_Text;
        TLabel *Label_Text_Password;
        TEdit *Edit_Text_Password;
        TButton *Button_Text_Keyfile;
        TLabel *Label_Text_Verif;
        TEdit *Edit_Text_Verif;
        TButton *Button_Text_Crypt_Action;
        TBitBtn *Button_Text_Stop;
        TEdit *Edit_Text_Keyfile;
        TLabel *Label_Text_Keyfile;
        TButton *Button_Text_Decrypt_Action;
        TPanel *Panel12;
        TTrackBar *TrackBar1;
        TLabel *Label_Keytitle;
        TLabel *Label_Keylength;
        TGroupBox *GroupBox5;
        TPanel *Panel9;
        TLabel *Label23;
        TLabel *Label_Logs_Time;
        TProgressBar *ProgressBar1;
        TPanel *Panel14;
        TImage *Image3;
        TPanel *Panel15;
        TLabel *Label_Version;
        TLabel *Label14;
        TLabel *Label13;
        TLabel *Label18;
        TPanel *Panel2;
        TBitBtn *BitBtn3;
        TPanel *Panel16;
        TGroupBox *GroupBox8;
        TGroupBox *GroupBox3;
        TButton *Button15;
        TLabel *Label_Action_Tittle;
        TLabel *Label_Action;
        TLabel *Label_Power_Tittle;
        TLabel *Label_Logs_Tittle;
        TLabel *Label_Min_Password_Tittle;
        TLabel *Label_Min_Password;
        TLabel *Label_Max_Password_Tittle;
        TLabel *Label_Max_Password;
        TLabel *Label_Keyinfo_Tittle;
        TLabel *Label_Keyinfo;
        TBitBtn *BitBtn4;
        TPageControl *PageControl2;
        TTabSheet *TabSheet7;
        TTabSheet *TabSheet8;
        TTabSheet *TabSheet9;
        TComboBox *Combo_Bssl;
        TLabel *Label31;
        TPanel *Panel11;
        TLabel *Label4;
        TComboBox *Combo_Power;
        TLabel *Label10;
        TComboBox *Combo_Keytype;
        TLabel *Label3;
        TComboBox *Combo_Logs;
        TPanel *Panel13;
        TLabel *Label11;
        TLabel *Label5;
        TLabel *Label9;
        TLabel *Label25;
        TComboBox *Combo_Mode;
        TComboBox *Combo_Method;
        TComboBox *Combo_Random;
        TComboBox *Combo_Priority;
        TPanel *Panel17;
        TLabel *Label30;
        TLabel *Label1;
        TLabel *Label2;
        TLabel *Label8;
        TLabel *Label28;
        TLabel *Label29;
        TPanel *Panel18;
        TPanel *Panel19;
        TLabel *Label32;
        TEdit *Edit_Bc;
        TEdit *Edit_Bs;
        TEdit *Edit_Round;
        TEdit *Edit_Buffer;
        TCheckBox *Check_Shuffle;
        TCheckBox *Check_Round;
        TCheckBox *Check_Buffer;
        TCheckBox *Check_Swap;
        TEdit *Edit_Swap;
        TPanel *Panel20;
        TLabel *Label26;
        TLabel *Label27;
        TSpeedButton *Speed_Bssl;
        TSpeedButton *Speed_Logs;
        TLabel *Label_Bssl_Tittle;
        TSpeedButton *Speed_Power;
        TLabel *Label_Cipher_Tittle;
        TSpeedButton *Speed_Cipher;
        TLabel *Label_Log_Keytype;
        TSpeedButton *Speed_Keytype;
        void __fastcall SlideMouseDown(TObject *Sender,
          TMouseButton Button, TShiftState Shift, int X, int Y);
        void __fastcall Button_Crypt_SourceClick(TObject *Sender);
        void __fastcall Button_Crypt_DestClick(TObject *Sender);
        void __fastcall Button_Crypt_KeyfileClick(TObject *Sender);
        void __fastcall Button_Crypt_ActionClick(TObject *Sender);
        void __fastcall Button_Decrypt_ActionClick(TObject *Sender);
        void __fastcall Button_Decrypt_SourceClick(TObject *Sender);
        void __fastcall Button_Decrypt_DestClick(TObject *Sender);
        void __fastcall Button_Decrypt_KeyfileClick(TObject *Sender);
        void __fastcall Edit_Decrypt_KeyfileChange(TObject *Sender);
        void __fastcall FormCreate(TObject *Sender);
        void __fastcall Combo_KeytypeChange(TObject *Sender);
        void __fastcall Button3Click(TObject *Sender);
        void __fastcall Button4Click(TObject *Sender);
        void __fastcall Button5Click(TObject *Sender);
        void __fastcall Radio_Keyfile_RandomClick(TObject *Sender);
        void __fastcall Radio_Keyfile_PasswordClick(TObject *Sender);
        void __fastcall BitBtn2Click(TObject *Sender);
        void __fastcall BitBtn1Click(TObject *Sender);
        void __fastcall Radio_Hide_HideClick(TObject *Sender);
        void __fastcall Radio_Hide_ExtractClick(TObject *Sender);
        void __fastcall Radio_Hide_EndClick(TObject *Sender);
        void __fastcall Radio_Hide_BeginingClick(TObject *Sender);
        void __fastcall SpeedButton1Click(TObject *Sender);
        void __fastcall SpeedButton2Click(TObject *Sender);
        void __fastcall SpeedButton3Click(TObject *Sender);
        void __fastcall Button_Hide_ActionClick(TObject *Sender);
        void __fastcall Button7Click(TObject *Sender);
        void __fastcall Button8Click(TObject *Sender);
        void __fastcall Button_Keyfile_ActionClick(TObject *Sender);
        void __fastcall BitBtn3Click(TObject *Sender);
        void __fastcall Button6Click(TObject *Sender);
        void __fastcall Button9Click(TObject *Sender);
        void __fastcall Button10Click(TObject *Sender);
        void __fastcall Button11Click(TObject *Sender);
        void __fastcall Button12Click(TObject *Sender);
        void __fastcall Edit_BsExit(TObject *Sender);
        void __fastcall Edit_RoundExit(TObject *Sender);
        void __fastcall Timer1Timer(TObject *Sender);
        void __fastcall Button_Crypt_StopClick(TObject *Sender);
        void __fastcall Button_Decrypt_StopClick(TObject *Sender);
        void __fastcall Button_Keyfile_StopClick(TObject *Sender);
        void __fastcall Button_Hide_StopClick(TObject *Sender);
        void __fastcall Combo_ModeChange(TObject *Sender);
        void __fastcall Combo_MethodChange(TObject *Sender);
        void __fastcall Button_Text_StopClick(TObject *Sender);
        void __fastcall Button_Text_CryptClick(TObject *Sender);
        void __fastcall Button_Text_KeyfileClick(TObject *Sender);
        void __fastcall Button_Text_Crypt_ActionClick(TObject *Sender);
        void __fastcall Button_Text_DecryptClick(TObject *Sender);
        void __fastcall Button_Text_Decrypt_ActionClick(TObject *Sender);
        void __fastcall TrackBar1Change(TObject *Sender);
        void __fastcall Button15Click(TObject *Sender);
        void __fastcall Combo_PriorityChange(TObject *Sender);
        void __fastcall PageControl1Change(TObject *Sender);
        void __fastcall Choice_Info();
        void __fastcall Choice_Bssl();
        void __fastcall Combo_PowerChange(TObject *Sender);
        void __fastcall Combo_LogsChange(TObject *Sender);
        void __fastcall BitBtn4Click(TObject *Sender);
        void __fastcall FormClose(TObject *Sender, TCloseAction &Action);
        void __fastcall Combo_BsslChange(TObject *Sender);
        void __fastcall Speed_BsslClick(TObject *Sender);
        void __fastcall Edit_BcChange(TObject *Sender);
        void __fastcall Edit_BsChange(TObject *Sender);
        void __fastcall Edit_RoundChange(TObject *Sender);
        void __fastcall Edit_BufferChange(TObject *Sender);
        void __fastcall Check_ShuffleClick(TObject *Sender);
        void __fastcall Check_RoundClick(TObject *Sender);
        void __fastcall Check_BufferClick(TObject *Sender);
        void __fastcall Check_SwapClick(TObject *Sender);
        void __fastcall Speed_PowerClick(TObject *Sender);
        void __fastcall Speed_CipherClick(TObject *Sender);
        void __fastcall Speed_LogsClick(TObject *Sender);
        void __fastcall Speed_KeytypeClick(TObject *Sender);

private:	// User declarations

public:		// User declarations
        __fastcall TForm_Main(TComponent* Owner);

};
//---------------------------------------------------------------------------
extern PACKAGE TForm_Main *Form_Main;

 class thbcrypt : public TThread
{
private:
protected:
        void __fastcall Execute();

public:
        __fastcall thbcrypt(void);
        void __fastcall progress();
        void __fastcall button_end();

};


class thtext_bcrypt : public TThread
{
private:
protected:
        void __fastcall Execute();

public:
        __fastcall thtext_bcrypt(void);
        void __fastcall progress();
        void __fastcall button_end();
};

class thdecrypt : public TThread
{
private:
protected:
        void __fastcall Execute();
public:
        __fastcall thdecrypt(void);
        void __fastcall progress();
        void __fastcall button_end();
};

class thtext_decrypt : public TThread
{
private:
protected:
        void __fastcall Execute();
public:
        __fastcall thtext_decrypt(void);
        void __fastcall progress();
        void __fastcall button_end();
};


class thbkey : public TThread
{
private:
protected:
        void __fastcall Execute();
public:
        __fastcall thbkey(void);
        void __fastcall progress();
        void __fastcall button_end();
};


class thbhide : public TThread
{
private:
protected:
        void __fastcall Execute();
public:
        __fastcall thbhide(void);
        void __fastcall progress();
        void __fastcall button_end();
};


void __fastcall OpenWebPage(char *);
char * __fastcall GetRegistryValue(char *);

//---------------------------------------------------------------------------
#endif
