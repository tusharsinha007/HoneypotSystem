@echo off
echo Staging files...
git add .

echo Committing files...
git config user.email "tusharsinha007@users.noreply.github.com"
git config user.name "Tushar Sinha"
git commit -m "Initial commit"

echo Setting branch to main...
git branch -M main

echo Adding remote repository...
git remote remove origin 2>nul
git remote add origin https://github.com/tusharsinha007/Honeypot_System.git

echo Pushing to GitHub...
git push -u origin main

echo.
echo Process complete! Press any key to exit.
pause
