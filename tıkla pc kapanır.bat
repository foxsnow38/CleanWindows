cd C:\windows temizleme && .\PureRa.exe
cd C:\windows temizleme\Wise Registry Cleaner && .\WiseRegCleaner.exe
DISM.exe /Online /Cleanup-Image /AnalyzeComponentStore
DISM.exe /Online /Cleanup-Image /StartComponentCleanup