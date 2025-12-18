Deployment steps (GitHub + Vercel)

1. Create a GitHub repository (example name: `jordan-encrypt-decrypt`).
2. In your project root run:

```bash
git init
git add .
git commit -m "Initial import: jordan-encrypt-decrypt"
git branch -M main
git remote add origin https://github.com/<your-username>/jordan-encrypt-decrypt.git
git push -u origin main
```

3. Go to https://vercel.com/new, import the `jordan-encrypt-decrypt` repository, and deploy.

Notes:
- Vercel will detect the `api` functions and serve `public` as static files.
- You can also install `vercel` CLI and run `npx vercel` to connect and deploy from the terminal.
