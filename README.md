# Http/Https Proxy
##问题

- 1.必须调用Hijack_Https函数保证能劫持Https，因为库中没有实现对Http/https的透明代理部分，所以不初始化https，造成https的数据请求出错，后果比较严重。
- 2.后续的库需要补充，所以在导出函数中没有对SSL初始化的释放操作，但aseSSLConfig中已经有相应功能
- 3.TrustRootCert和ExportRootCert函数必须在Hijack_Https函数调用后执行,因为Hijack_Https初始化了SSL库和生成了根证书的操作
- 4.有部分的内容更新可能没有代码的修改，只是代码整洁度的问题，后续还会调整

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
		
		FireFox浏览器支持问题：主要原因是Firefox证书使用导致

##感谢
		1)	Joe Klemencic's IMPORTPFX.exe的部分源代码