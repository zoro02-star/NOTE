https://attack.mitre.org/  - specific threat models and methodologies
book.hacktricks.xyz
### Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

### Select the language you want to use
export LANG="master" # Leave master for english
other commands : `docker ps` to view if docker container is created and running.
### Run the docker container indicating the path to the hacktricks folder

```
run-docker run -d --rm \
--platform linux/amd64 \
  -e LANG=master \
  -p 3337:3000 \
  --name hacktricks \
  -v $(pwd)/hacktricks:/app \
  ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image:latest \
  bash -c "mkdir -p ~/.ssh && \
  ssh-keyscan -H github.com >> ~/.ssh/known_hosts && \
  cd /app && \
  git config --global --add safe.directory /app && \
  git checkout master && \
  git pull && \
  MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```


Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337/)** after <5 minutes (it needs to build the book, be patient).

![[Pasted image 20260111003100.png]]
![[Pasted image 20260111003117.png]]