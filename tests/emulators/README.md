## Local Emulators

1. Ensure that you have latest version of `firebase cli` ( **> 8.16.0** ):

```shell script
curl -sL firebase.tools | upgrade=true bash

$ firebase -V
8.16.2
```

2. Start Emulators

```shell script
firebase emulators:start
```

3. Export Env variables:

```dotenv
export GOOGLE_APPLICATION_CREDENTIALS="test-service-account.json"
export FIREBASE_AUTH_EMULATOR_HOST="localhost:9090"
export FIRESTORE_EMULATOR_HOST="localhost:8080"
```

4. Troubleshooting 

```shell script
# List Process that takes some ports
lsof -i -P -n  | grep -E '9000|8080|9090|4040'

# Kill this processes
kill $(lsof -i -P -n  | grep -E '9000|8080|9090|4040' | awk '{ print $2 }')
```
