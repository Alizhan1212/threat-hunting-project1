# CALDERA lab setup on macOS (for the "at possibility" screenshots)

This runs the whole thing on your Mac without touching your real system. The CALDERA
server and the victim agent both run in Docker, so your macOS is never the target.
Works on Apple Silicon and Intel.

> Isolated lab only. The agent runs inside a container you own. Nothing here attacks
> real users, accounts, or the real Kaspi/eGov/Kazpost/CDEK services.

## 0. Prerequisites
- Docker Desktop for Mac (install from docker.com, free).
- ~5 GB free disk.

## 1. Get CALDERA
```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
```

## 2. Start the server (Docker)
```bash
docker build --build-arg WIN_BUILD=false -t caldera:server .
docker run -p 8888:8888 caldera:server
```
Open http://localhost:8888 — log in with the credentials printed in the container logs
(default user `red`, password shown on first start / in `conf/`).

## 3. Deploy an agent (the lab "victim")
- In the UI go to **Agents → Deploy an agent → Sandcat (54ndc47)**.
- Pick a platform and copy the one-line command.
- Run that command **inside a throwaway container or VM you own**, e.g.:
```bash
docker run -it --rm --network host ubuntu:22.04 bash
# then paste the agent deploy command inside that container
```
The agent appears in **Agents** when it checks in.

## 4. Load the profile
- Put `profile.yml` under `data/adversaries/` (or **Adversaries → + → import**).
- Fill the `REPLACE_WITH_UUID` slots using real ability UUIDs from **Abilities**
  (search by the ability name in each comment).

## 5. Run the operation and capture screenshots
- **Operations → + New** → pick your adversary profile + the agent → **Start**.
- Take screenshots of:
  1. The operation timeline showing each ability run (persistence → discovery → collection → exfil)
  2. The ATT&CK technique IDs next to each step
  3. The fact/result output for the exfil step (to the in-lab sink)
- Save them in `week-08/screenshots/`.

## 6. Tear down
```bash
# stop the server container (Ctrl-C), remove the throwaway agent container
docker ps -a        # find leftover containers
docker rm -f <id>   # remove them
```

## If you don't have time
The profile + the plan + detection mapping are enough to pass the deliverable
(the task says emulation is "at possibility"). Screenshots are a bonus for the defence.
