@echo off

type NUL && "%CODEQL_EXTRACTOR_TEAL_ROOT%\tools\win64\extractor.exe" ^
        extract ^
        --file-list "%1" ^
        --source-archive-dir "%CODEQL_EXTRACTOR_TEAL_SOURCE_ARCHIVE_DIR%" ^
        --output-dir "%CODEQL_EXTRACTOR_TEAL_TRAP_DIR%"

exit /b %ERRORLEVEL%
