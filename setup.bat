@echo off
echo ========================================
echo Setting up Decentralized Smart Metering Protocol
echo ========================================
echo.
echo Creating build directory...
mkdir build 2>nul

echo Running CMake...
cd build
cmake ..

echo.
echo ========================================
echo Setup complete!
echo ========================================
echo.
echo Next steps:
echo   cd build
echo   cmake --build . --config Release
echo   .\Release\smart_meter_simulation.exe
echo.
pause
