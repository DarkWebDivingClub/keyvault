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

This needs **two** patched forks installed into `~/.m2` first, in this
order — neither is on any public repository:

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

git clone https://github.com/DarkWebDivingClub/nostr-java.git
cd nostr-java && mvn install -DskipTests && cd ..

git clone https://github.com/DarkWebDivingClub/bitcoinj.git
cd bitcoinj && ./gradlew publishToMavenLocal && cd ..
```

`club.dwdc.keyvault.core` needs `org.bitcoinj:bitcoinj-core:0.18-dwdc.1`,
and `club.dwdc.keyvault.nostr` needs
`xyz.tcheeric:nostr-java-identity:2.4.2-dwdc.1` for `nostr.id.IIdentity`
— a class present in no upstream release. Both forks carry a `FORK.md`
explaining what is patched and why.

JDK 21 is required and must be set explicitly: Gradle 8.13 cannot parse
JDK 25 class files, and JDK 25 is the default `java` on current Ubuntu.

Android dependency target:

```kotlin
implementation("club.dwdc:club.dwdc.keyvault.nostr:0.4.0")
```

## License

This project is licensed under the GNU General Public License v3.0 only
(`GPL-3.0-only`). See [LICENSE](LICENSE).
