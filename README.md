# Http/Https Proxy
##不再更新此分支
##问题

- 1.必须调用Hijack_Https函数保证能劫持Https，因为库中没有实现对Http/https的透明代理部分，所以不初始化https，造成https的数据请求出错，后果比较严重。
- 2.后续的库需要补充，所以在导出函数中没有对SSL初始化的释放操作，但aseSSLConfig中已经有相应功能
- 3.TrustRootCert和ExportRootCert函数必须在Hijack_Https函数调用后执行,因为Hijack_Https初始化了SSL库和生成了根证书的操作
- 4.对于SSL部分，有部分功能欠缺，不能根据不同的url实现对CA签名，后续这部分需要补充.(CA证书签名已经加入到CertificateProvider.h(cpp)中)
- 5.修复缺少stdint.h文件不能编译通过的问题，因为stdint.h包含在C99中，而vs2008使用C89库，所以造成文件缺失。快速的解决办法就是把高版本(vs2010以上)vc/include目录下的stdint.h拷贝到vc2008下的vc/include下就可以了

##API文档
		PHS_HANDLE  __stdcall Create_ProxyHttpService(HTTPSERVICE_PARAMS *pHttpService_params);
		参数：
		pHttpService_params:　传入服务器的参数，结构请参考HTTPSERVICE_PARAMS
		返回值:
		PHS_HANDLE:	代理服务句柄
		
		BOOL        __stdcall Start_ProxyHttpService(PHS_HANDLE handle);
		参数:
		handle:	传入由Create_ProxyHttpService函数创建的句柄
		返回值:
		启动服务成功，返回TRUE,失败返回FALSE
		
		BOOL        __stdcall Stop_ProxyHttpService(PHS_HANDLE handle);
		参数:
		handle:	传入由Create_ProxyHttpService创建的句柄
		返回值:
		停止服务成功返回TRUE,失败返回FALSE

		SCG_HANDLE  __stdcall Hijack_Https(PHS_HANDLE handle);
		参数:
		handle:	传入由Create_ProxyHttpService创建的句柄
		返回值:
		SCG_HANDLE:	对https劫持基础配置句柄
		
		BOOL        __stdcall TrustRootCert(SCG_HANDLE handle);
		参数:
		handle:	Hjjack_Https函数创建句柄
		返回值:
		把创建的基础根证书添加到系统的根证书信任中，如果成功，则返回TRUE,否则返回FALSE

		BOOL        __stdcall ExportRootCert(/*IN*/SCG_HANDLE handle,/*OUT*/unsigned char *buf, int *len);
		参数:
		handle:	Hijack_Https创建的句柄
		buf:	获取证书的内容
		len:	输入时作为buf的长度，返回成功后得到证书的实际长度
		返回值:
		正确得到生成的根证书内容，则返回TRUE,否则返回FALSE
##说明
		
		目前这个Http(Https)的代理服务器，只是功能验证，没有对库的稳定性和内存部分作更进一步的测试，
		会陆续改进，也可能架构重写。还有为什么我要写这个Https代理的验证程序，主要验证Https中间人劫持。

##补充说明
		对于IE浏览器，可以通过在系统中添加信任证书的方式，使访问https网站无差别，但Firefox,Chrome都有问题，
		是不是可以通过其他的方式解决？？

##感谢
		1)	Joe Klemencic's IMPORTPFX.exe的部分源代码