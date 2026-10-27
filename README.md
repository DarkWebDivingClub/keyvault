# club.dwdc.keyvault

Minimal DWDC KeyVault library extracted from the existing IZ KeyVault codebase.

This repo intentionally starts with only the modules currently needed by the Android KeyMaster app:

- `club.dwdc.keyvault.core`
- `club.dwdc.keyvault.nostr`

The current KeyVault, KeyMaster, Avatar, and host-service architecture is
described in [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md).

Build locally:

```sh
mvn test
mvn install
```

This needs the patched bitcoinj fork in `~/.m2` first. `keyvault.core`
depends on `org.bitcoinj:bitcoinj-core:0.18-dwdc.1`, which is not on any
public repository, so build and install it before keyvault:

```sh
cd ~/git/bitcoinj
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 ./gradlew publishToMavenLocal
```

JDK 21 is required and must be set explicitly: Gradle 8.13 cannot parse
JDK 25 class files, and JDK 25 is the default `java` on current Ubuntu.

Android dependency target:

```kotlin
implementation("club.dwdc:club.dwdc.keyvault.nostr:0.3.0")
```

## License

This project is licensed under the GNU General Public License v3.0 only
(`GPL-3.0-only`). See [LICENSE](LICENSE).
