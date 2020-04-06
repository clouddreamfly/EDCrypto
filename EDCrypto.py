#!/usr/bin/python
#-*-coding:utf-8-*-

import os
import wx
from hashlib import md5, sha1
import base64
import struct
import random


#定义
ENCRYPT_KEY_LEN = 8                                 #密钥长度
MAX_SOURCE_LEN = 256				    #最大长度
MAX_ENCRYPT_LEN	= MAX_SOURCE_LEN * ENCRYPT_KEY_LEN  #最大长度



#生成密文
def XorEncrypt(SourceData, MaxCount):
    
    #变量定义
    EncryptData = ""

    #生成密钥
    RandKey = [ 0 for i in range(ENCRYPT_KEY_LEN)]
    RandKey[0] = len(SourceData)

    for i in range(1, len(RandKey)): 
        RandKey[i] = random.randint(0, 0xFFFF) % 0xFFFF

    #步骤准备
    EncryptTimes = ((RandKey[0] + ENCRYPT_KEY_LEN - 1) // ENCRYPT_KEY_LEN) * ENCRYPT_KEY_LEN

    #参数效验
    if (EncryptTimes * ENCRYPT_KEY_LEN + 1) > MaxCount :
        return False

    #生成密文
    TempCode = 0
    for i in range(EncryptTimes):
        if i < RandKey[0]:
            TempCode = ord(SourceData[i]) ^ RandKey[i % ENCRYPT_KEY_LEN]
        else: 
            TempCode = RandKey[i % ENCRYPT_KEY_LEN] ^ (random.randint(0, 0xFFFF) % 0xFFFF)

        EncryptData += u"%04X%04X" % (RandKey[i % ENCRYPT_KEY_LEN], TempCode)

    return True, EncryptData


#解开密文
def XorDecrypt(EncryptData, MaxCount):

    #变量定义
    SourceData = ""

    #效验长度
    EncryptLength = len(EncryptData)
    if EncryptLength < ENCRYPT_KEY_LEN * ENCRYPT_KEY_LEN: 
        return False

    #获取长度
    SourceLength = int(EncryptData[0 : 4], 16)

    #长度效验
    if (EncryptLength != (((SourceLength + ENCRYPT_KEY_LEN - 1) // ENCRYPT_KEY_LEN) * ENCRYPT_KEY_LEN * ENCRYPT_KEY_LEN)):
        return False

    #长度效验
    if (SourceLength + 1) > MaxCount:
        return False

    #解开密码
    for i in range(SourceLength):

        #获取密钥
        index = i * 8
        Key = EncryptData[ index : index + 4]
        Data = EncryptData[index + 4 : index + 8]

        #提取密钥
        Key = int(Key, 16)
        Data = int(Data, 16)

        #生成原文
        SourceData += unichr(Key ^ Data)

    return True, SourceData


#获取网络地址
def GetMacAddress():
    """Get the hardware address on Windows using NetBIOS calls.
    See http://support.microsoft.com/kb/118623 for details."""
    import win32wnet, netbios
    ncb = netbios.NCB()
    ncb.Command = netbios.NCBENUM
    ncb.Buffer = adapters = netbios.LANA_ENUM()
    adapters._pack()
    if win32wnet.Netbios(ncb) != 0:
        return
    adapters._unpack()
    for i in range(adapters.length):
        ncb.Reset()
        ncb.Command = netbios.NCBRESET
        ncb.Lana_num = ord(adapters.lana[i])
        if win32wnet.Netbios(ncb) != 0:
            continue
        ncb.Reset()
        ncb.Command = netbios.NCBASTAT
        ncb.Lana_num = ord(adapters.lana[i])
        ncb.Callname = '*'.ljust(16)
        ncb.Buffer = status = netbios.ADAPTER_STATUS()
        if win32wnet.Netbios(ncb) != 0:
            continue
        status._unpack()
        bytes = map(ord, status.adapter_address)
        return ((bytes[0]<<40L) + (bytes[1]<<32L) + (bytes[2]<<24L) +
                (bytes[3]<<16L) + (bytes[4]<<8L) + bytes[5])


class MainDialog(wx.Dialog):
    """window show"""

        
    
    def __init__(self):
        wx.Log().SetLogLevel(0)
        wx.Dialog.__init__(self,parent=None,id=-1,title = u'常用工具',size = (960,600))
        
        self.SetWindowStyle(self.GetWindowStyle() | wx.MINIMIZE_BOX)
        
        #创建子空间
        self.OnCreateWindow()
            
            
    def OnCreateWindow(self, *arg):
        #创建控件
        panel = wx.Panel(self)
        frame_sizer = wx.BoxSizer(orient=wx.VERTICAL)
        panel.SetSizer(frame_sizer)
        
        label_ende_crypto = wx.StaticBox(panel, label=u"加解密\编解码:")
        frame_sizer1 = wx.StaticBoxSizer(label_ende_crypto, orient=wx.VERTICAL)
        frame_sizer.Add(frame_sizer1, 1, wx.ALL|wx.EXPAND, 2)
        
        panel_ende_crypto = wx.Panel(label_ende_crypto)
        frame_sizer1_1 = wx.BoxSizer(orient=wx.HORIZONTAL)
        panel_ende_crypto.SetSizer(frame_sizer1_1)
        frame_sizer1.Add(panel_ende_crypto, 1, wx.ALL|wx.EXPAND, 2)
        
        label_encode_text = wx.StaticBox(panel_ende_crypto, label=u"明文:")
        label_decode_text = wx.StaticBox(panel_ende_crypto, label=u"密文:")
        self.text_encode_content = wx.TextCtrl(panel_ende_crypto, style=wx.TE_MULTILINE|wx.TE_AUTO_SCROLL)
        self.text_decode_content = wx.TextCtrl(panel_ende_crypto, style=wx.TE_MULTILINE|wx.TE_AUTO_SCROLL)

        frame_sizer1_1_1 = wx.StaticBoxSizer(label_encode_text, orient=wx.VERTICAL)
        frame_sizer1_1_2 = wx.StaticBoxSizer(label_decode_text, orient=wx.VERTICAL)
        frame_sizer1_1_1.Add(self.text_encode_content, 1, wx.ALL|wx.EXPAND, 0)
        frame_sizer1_1_2.Add(self.text_decode_content, 1, wx.ALL|wx.EXPAND, 0)   
        frame_sizer1_1.Add(frame_sizer1_1_1, 1, wx.ALL|wx.EXPAND, 0)
        frame_sizer1_1.Add(frame_sizer1_1_2, 1, wx.ALL|wx.EXPAND, 0)

     
        frame_sizer1_2 = wx.BoxSizer(orient=wx.HORIZONTAL)
        frame_sizer1.AddSpacer(6)
        frame_sizer1.Add(frame_sizer1_2, 0, wx.ALL|wx.ALIGN_CENTER_HORIZONTAL, 2)     
        
        
        label_secret_key = wx.StaticText(panel, label=u"密钥：")
        text_secret_key = wx.TextCtrl(panel, size=(160, -1))
        btn_md5_encrypto = wx.Button(panel, label=u"MD5 加密")
        btn_sha1_encrypto = wx.Button(panel, label=u"SHA1 加密")  
        btn_xor_encrypto = wx.Button(panel, label=u"XOR 加密")
        btn_xor_decrypto = wx.Button(panel, label=u"XOR 解密")
        btn_base64_encrypto = wx.Button(panel, label=u"BASE64 加密")
        btn_base64_decrypto = wx.Button(panel, label=u"BASE64 解密")        
        btn_utf8_encode = wx.Button(panel, label=u"UTF8 编码")
        btn_utf8_decode = wx.Button(panel, label=u"UTF8 解码")        
        
        frame_sizer1_2.Add(label_secret_key, 0, wx.ALIGN_CENTER_VERTICAL)   
        frame_sizer1_2.Add(text_secret_key, 0, wx.ALIGN_CENTER_VERTICAL)   
        frame_sizer1_2.Add(btn_md5_encrypto, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 8)
        frame_sizer1_2.Add(btn_sha1_encrypto, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4)   
        frame_sizer1_2.Add(btn_xor_encrypto, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4)
        frame_sizer1_2.Add(btn_xor_decrypto, 0, wx.ALIGN_CENTER_VERTICAL)        
        frame_sizer1_2.Add(btn_base64_encrypto, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4)
        frame_sizer1_2.Add(btn_base64_decrypto, 0, wx.ALIGN_CENTER_VERTICAL)                
        frame_sizer1_2.Add(btn_utf8_encode, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4) 
        frame_sizer1_2.Add(btn_utf8_decode, 0, wx.ALIGN_CENTER_VERTICAL) 
        
        frame_sizer2 = wx.BoxSizer(orient=wx.HORIZONTAL)
        frame_sizer.Add(frame_sizer2, 0, wx.ALL|wx.EXPAND, 2)        
        
        frame_sizer3 = wx.BoxSizer(orient=wx.HORIZONTAL)
        frame_sizer.Add(frame_sizer3, 0, wx.ALL|wx.EXPAND, 2)
        
        label_net_address = wx.StaticText(panel, label=u"网络地址：")
        self.text_net_address_encode = wx.TextCtrl(panel, value=u"127.0.0.1", size=(160, -1))
        self.text_net_address_decode = wx.TextCtrl(panel, size=(160, -1))              
        btn_ipv4_encode = wx.Button(panel, label=u"IPV4 编码")
        btn_ipv4_decode = wx.Button(panel, label=u"IPV4 解码")
        btn_ipv6_encode = wx.Button(panel, label=u"IPV6 编码")
        btn_ipv6_decode = wx.Button(panel, label=u"IPV6 解码") 
        frame_sizer3.Add(label_net_address, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 10) 
        frame_sizer3.Add(self.text_net_address_encode, 0, wx.ALIGN_CENTER_VERTICAL) 
        frame_sizer3.Add(self.text_net_address_decode, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4) 
        frame_sizer3.Add(btn_ipv4_encode, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4) 
        frame_sizer3.Add(btn_ipv4_decode, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4)            
        frame_sizer3.Add(btn_ipv6_encode, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4) 
        frame_sizer3.Add(btn_ipv6_decode, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4)              
        
        frame_sizer4 = wx.BoxSizer(orient=wx.HORIZONTAL)
        frame_sizer.Add(frame_sizer4, 0, wx.ALL|wx.EXPAND, 2)   
        
        label_program_version = wx.StaticText(panel, label=u"程序版本：")
        self.text_version_encode = wx.TextCtrl(panel, value=u"1.0.0.1", size=(160, -1))
        self.text_version_decode = wx.TextCtrl(panel, size=(160, -1))        
        btn_version_encode = wx.Button(panel, label=u"版本编码")
        btn_version_decode = wx.Button(panel, label=u"版本解码")
        frame_sizer4.Add(label_program_version, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 10) 
        frame_sizer4.Add(self.text_version_encode, 0, wx.ALIGN_CENTER_VERTICAL) 
        frame_sizer4.Add(self.text_version_decode, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4) 
        frame_sizer4.Add(btn_version_encode, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4) 
        frame_sizer4.Add(btn_version_decode, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4)           
        
        frame_sizer5 = wx.BoxSizer(orient=wx.HORIZONTAL)
        frame_sizer.Add(frame_sizer5, 0, wx.ALL|wx.EXPAND, 2)          
        
        label_prime_number = wx.StaticText(panel, label=u"质数数值：")
        self.text_prime_number1 = wx.TextCtrl(panel, value=u"2053", size=(160, -1))
        self.text_prime_number2 = wx.TextCtrl(panel, size=(160, -1), style=wx.TE_READONLY)
        btn_prime_number = wx.Button(panel, label=u"生成质数")
        frame_sizer5.Add(label_prime_number, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 10)
        frame_sizer5.Add(self.text_prime_number1, 0, wx.ALIGN_CENTER_VERTICAL)
        frame_sizer5.Add(self.text_prime_number2, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4)
        frame_sizer5.Add(btn_prime_number, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4)
        
        
        frame_sizer6 = wx.BoxSizer(orient=wx.HORIZONTAL)
        frame_sizer.Add(frame_sizer6, 0, wx.ALL|wx.EXPAND, 2)         
        
        label_machine_id = wx.StaticText(panel, label=u"机器标识：")
        self.text_machine_id = wx.TextCtrl(panel, size=(360, -1), style=wx.TE_READONLY)
        btn_machine_id = wx.Button(panel, label=u"生成机器码")
        frame_sizer6.Add(label_machine_id, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 10)
        frame_sizer6.Add(self.text_machine_id, 0, wx.ALIGN_CENTER_VERTICAL)
        frame_sizer6.Add(btn_machine_id, 0, wx.ALIGN_CENTER_VERTICAL|wx.LEFT, 4)
    
        frame_sizer.AddSpacer(6)
        
        
        #事件绑定
        self.Bind(wx.EVT_BUTTON, self.OnClickedMD5Encrypto, btn_md5_encrypto)
        self.Bind(wx.EVT_BUTTON, self.OnClickedSHA1Encrypto, btn_sha1_encrypto)
        self.Bind(wx.EVT_BUTTON, self.OnClickedXorEncrypto, btn_xor_encrypto)
        self.Bind(wx.EVT_BUTTON, self.OnClickedXorDecrypto, btn_xor_decrypto)
        self.Bind(wx.EVT_BUTTON, self.OnClickedBase64Encrypto, btn_base64_encrypto)
        self.Bind(wx.EVT_BUTTON, self.OnClickedBase64Decrypto, btn_base64_decrypto)
        self.Bind(wx.EVT_BUTTON, self.OnClickedUTF8Encode, btn_utf8_encode)
        self.Bind(wx.EVT_BUTTON, self.OnClickedUTF8Decode, btn_utf8_decode)
        
        self.Bind(wx.EVT_BUTTON, self.OnClickedIPV4Encode, btn_ipv4_encode)
        self.Bind(wx.EVT_BUTTON, self.OnClickedIPV4Decode, btn_ipv4_decode)
        self.Bind(wx.EVT_BUTTON, self.OnClickedIPV6Encode, btn_ipv6_encode)
        self.Bind(wx.EVT_BUTTON, self.OnClickedIPV6Decode, btn_ipv6_decode)      
        
        self.Bind(wx.EVT_BUTTON, self.OnClickedVersionEncode, btn_version_encode)
        self.Bind(wx.EVT_BUTTON, self.OnClickedVersionDecode, btn_version_decode)      
        
        self.Bind(wx.EVT_BUTTON, self.OnClickedPrimeNumber, btn_prime_number)     
        
        self.Bind(wx.EVT_BUTTON, self.OnClickedMachineID, btn_machine_id)       
        
        
            
    def OnClickedMD5Encrypto(self, evt):
        
        encrypto_content = self.text_encode_content.GetValue()
        if encrypto_content == "":
            return
        
        obj = md5()
        obj.update(encrypto_content)
        decrypto_content = obj.hexdigest()

        self.text_decode_content.SetValue(decrypto_content)
        
    def OnClickedSHA1Encrypto(self, evt):
        
        encrypto_content = self.text_encode_content.GetValue()
        if encrypto_content == "":
            return
        
        obj = sha1()
        obj.update(encrypto_content)
        decrypto_content = obj.hexdigest()
        self.text_decode_content.SetValue(decrypto_content)        
    
    def OnClickedXorEncrypto(self, evt):
        
        encrypto_content = self.text_encode_content.GetValue()
        if encrypto_content == "":
            return
        
        try:
            result, decrypto_content = XorEncrypt(encrypto_content, MAX_ENCRYPT_LEN)
            if result == True:
                self.text_decode_content.SetValue(decrypto_content)
            else:
                wx.MessageBox(u"XOR加密失败", u"错误提示", wx.OK, self)
        except:
            wx.MessageBox(u"XOR加密失败", u"错误提示", wx.OK, self)
        
    
    def OnClickedXorDecrypto(self, evt):
        
        decrypto_content = self.text_decode_content.GetValue()
        if decrypto_content == "":
            return
        
        try:
            result, encrypto_content = XorDecrypt(decrypto_content, MAX_SOURCE_LEN)    
            if result == True:
                self.text_encode_content.SetValue(encrypto_content)
            else:
                wx.MessageBox(u"XOR解密失败", u"错误提示", wx.OK, self)
        except:
            wx.MessageBox(u"XOR解密失败", u"错误提示", wx.OK, self)
            
    
    def OnClickedBase64Encrypto(self, evt):
        
        encrypto_content = self.text_encode_content.GetValue()
        if encrypto_content == "":
            return
        
        decrypto_content = base64.b64encode(encrypto_content)

        self.text_decode_content.SetValue(decrypto_content)
    
    def OnClickedBase64Decrypto(self, evt):
        
        decrypto_content = self.text_decode_content.GetValue()
        if decrypto_content == "":
            return
        
        try:
            encrypto_content = base64.b64decode(decrypto_content)    
            self.text_encode_content.SetValue(encrypto_content)
        except TypeError, e:
            wx.MessageBox(unicode(e), u"错误提示", wx.OK, self)
        except:
            wx.MessageBox(u"BASE64解密错误", u"错误提示", wx.OK, self)
        
    
    def OnClickedUTF8Encode(self, evt):
        
        encode_content = self.text_encode_content.GetValue()
        if encode_content == "":
            return

        decode_datas = encode_content.encode("utf-8") 
        decode_content = u""
        for data in decode_datas:
            if ord(data) >= 0x80 or data == '%':
                decode_content += u"%%%X"%(ord(data))
            else:
                decode_content += data
            
        self.text_decode_content.SetValue(decode_content)   
    
    def OnClickedUTF8Decode(self, evt):
        
        decode_content = self.text_decode_content.GetValue()
        if decode_content == "":
            return
        
        try:
            encode_content = ""
            index = 0
            while index < len(decode_content):
                data = decode_content[index]
                if data == u"%":
                    encode_content += chr(int(decode_content[index + 1 : index + 3], 16))
                    index += 3
                else:   
                    encode_content += chr(ord(data))
                    index += 1
            
            encode_content = encode_content.decode("utf-8") 
            self.text_encode_content.SetValue(encode_content)
        except:
            wx.MessageBox(u"UTF8解码错误", u"错误提示", wx.OK, self)
    
    
    def OnClickedIPV4Encode(self, evt):
        
        net_address_content = self.text_net_address_encode.GetValue()
        if net_address_content == "":
            return
        
        def check(values): 
            for value in values: 
                if not value.isdigit() : return False 
                value = int(value)
                if value < 0 or value > 255: return False
                
            return True
        
        net_address_list = net_address_content.split(u".")
        if len(net_address_list) != 4 or not check(net_address_list):
            wx.MessageBox(u"输入网络地址错误，示例：127.0.0.1", u"错误提示", wx.OK, self)
            return 
        
        net_address = (int(net_address_list[0]) & 0xFF) | ((int(net_address_list[1]) & 0xFF) << 8) | ((int(net_address_list[2]) & 0xFF) << 16) | ((int(net_address_list[3]) & 0xFF)  << 24)
        net_address_content = u"%d:%d" % (net_address, struct.unpack(">i", struct.pack(">I", net_address))[0])
        self.text_net_address_decode.SetValue(net_address_content)
    
    
    def OnClickedIPV4Decode(self, evt):
        
        net_address_content = self.text_net_address_decode.GetValue()
        if net_address_content == "":
            return
        
        def check(value):
            
            try:
                value = long(value)
                return isinstance(value, (int, long))
            except:
                return False
        
        net_address_content = net_address_content.split(u":")[0]
        if len(net_address_content) <= 0 or not check(net_address_content):
            wx.MessageBox(u"输入网络地址数字错误，示例：16777343", u"错误提示", wx.OK, self)
            return 
        
        net_address = int(net_address_content)
        net_address_content = u"%d.%d.%d.%d" % ((net_address & 0xFF), ((net_address >> 8) & 0xFF),  ((net_address >> 16) & 0xFF), ((net_address >> 24) & 0xFF))        
        self.text_net_address_encode.SetValue(net_address_content) 
    
    def OnClickedIPV6Encode(self, evt):
        
        self.OnClickedIPV4Encode(evt)    
    
    def OnClickedIPV6Decode(self, evt):
        
        self.OnClickedIPV4Decode(evt)
    
    
    def OnClickedVersionEncode(self, evt):
        
        version_content = self.text_version_encode.GetValue()
        if version_content == "":
            return
        
        def check(values): 
            for value in values: 
                if not value.isdigit() : return False 
                
            return True
        
        version_list = version_content.split(u".")
        if len(version_list) != 4 or not check(version_list):
            wx.MessageBox(u"输入版本错误，示例：1.0.0.1", u"错误提示", wx.OK, self)
            return 
        
        version = ((int(version_list[0]) & 0xFF) << 24) | ((int(version_list[1]) & 0xFF) << 16) | ((int(version_list[2]) & 0xFF) << 8) | (int(version_list[3]) & 0xFF)
        self.text_version_decode.SetValue(unicode(version))
        
        
    def OnClickedVersionDecode(self, evt):
        
        version_content = self.text_version_decode.GetValue()
        if version_content == "":
            return
    
        if len(version_content) <= 0 or not version_content.isdigit():
            wx.MessageBox(u"输入版本数字错误，示例：16777217", u"错误提示", wx.OK, self)
            return 
        
        version = int(version_content)
        version_content = u"%d.%d.%d.%d" % (((version >> 24) & 0xFF), ((version >> 16) & 0xFF),  ((version >> 8) & 0xFF), (version & 0xFF))
        self.text_version_encode.SetValue(version_content)
    
    def OnClickedPrimeNumber(self, evt):  
        
        prime_content = self.text_prime_number1.GetValue()
        if prime_content == "":
            return
    
        if len(prime_content) <= 0 or not prime_content.isdigit():
            wx.MessageBox(u"输入质数数字错误，示例：13", u"错误提示", wx.OK, self)
            return 
        
        def IsPrime(value):
            
            if value <= 1:
                return False
            
            if value % 2 == 0:
                return False
            
            i = 3
            while i * i <= value:
                if value % i == 0:
                    return False
                i += 2
          
            return True            
            
        
        def CalcPrimeNumber(value):
            if value <= 2:
                return 2
            
            while not IsPrime(value):
                value += 1
          
            return value
        
        prime_number = int(prime_content)
        prime_number = CalcPrimeNumber(prime_number)
        self.text_prime_number2.SetValue(unicode(prime_number))        
        
    
    def OnClickedMachineID(self, evt):
        
        mac_address = GetMacAddress()
        mac_address_hex = ""
        for i in range(6): mac_address_hex += "%02X"%((mac_address >> ((5-i) * 8)) & 0xFF)

        obj = md5()
        obj.update(mac_address_hex)
        machine_id_content = obj.hexdigest().upper()
        
        self.text_machine_id.SetValue(machine_id_content)
    
        

class EDCryptoApp(wx.App):  

    def OnInit(self):
        dialog = MainDialog()
        dialog.ShowModal()
        dialog.Destroy()
        return True


def main():
    """software start runing """
    
    app = EDCryptoApp()  
    app.MainLoop()
    
    return

									
if __name__ == '__main__':
    main()

        
