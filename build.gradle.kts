import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask
import net.researchgate.release.GitAdapter.GitConfig
import net.researchgate.release.ReleaseExtension

// Top-level build file where you can add configuration options common to all sub-projects/modules.

plugins {
    `java-library`
    `maven-publish`
    signing
    jacoco
    alias(libs.plugins.spotless)
    alias(libs.plugins.versions)
    alias(libs.plugins.nexus.publish)
    alias(libs.plugins.release)
}

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        // NOTE: Do not place your application dependencies here; they belong
        // in the individual module build.gradle files
    }
}

repositories {
    mavenCentral()
    google()
}

group = "org.connectbot"

val gitHubUrl = "https://github.com/connectbot/trilead-ssh2"

apply(from = "$rootDir/config/quality.gradle.kts")

dependencies {
    implementation(libs.simplesocks)
    implementation(libs.tink) {
        isTransitive = false
    }
    implementation(libs.jbcrypt)
    implementation(libs.kyber)

    testImplementation(libs.logback.classic)
    testImplementation(libs.commons.codec)
    testImplementation(libs.commons.io)
    testImplementation(libs.hamcrest)
    testImplementation(libs.jetbrains.annotations)
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.junit.jupiter)
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation(libs.testcontainers)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(libs.junit.platform.launcher)
}

java {
    withJavadocJar()
    withSourcesJar()
    toolchain {
        val jdkVersion = (project.findProperty("jdkVersion") as String?)?.toIntOrNull() ?: 17
        languageVersion.set(JavaLanguageVersion.of(jdkVersion))
    }
}

tasks.test {
    useJUnitPlatform()
}

tasks.jacocoTestReport {
    reports {
        xml.required.set(true)
        csv.required.set(true)
    }
}

fun ReleaseExtension.git(configure: GitConfig.() -> Unit) = (getProperty("git") as GitConfig).configure()
release {
}

spotless {
    java {
        target(
            fileTree(".") {
                include("**/*.java")
                exclude("**/build", "**/out")
            },
        )
        removeUnusedImports()
        trimTrailingWhitespace()

        leadingSpacesToTabs()
        replaceRegex("class-level javadoc indentation fix", "^\\*", " *")
        replaceRegex("method-level javadoc indentation fix", "\t\\*", "\t *")
    }

    kotlinGradle {
        target(
            fileTree(".") {
                include("**/*.gradle.kts")
                exclude("**/build", "**/out")
            },
        )
        ktlint()
    }

    format("xml") {
        target(
            fileTree(".") {
                include("config/**/*.xml", "sshlib/**/*.xml")
                exclude("**/build", "**/out")
            },
        )

        eclipseWtp(EclipseWtpFormatterStep.XML).configFile("spotless.xml.prefs")
    }

    format("misc") {
        target("**/.gitignore")
        leadingSpacesToTabs()
        trimTrailingWhitespace()
        endWithNewline()
    }
}

fun isNonStable(version: String): Boolean =
    listOf("alpha", "beta", "rc", "cr", "m", "preview", "b", "ea")
        .map { qualifier -> Regex("(?i).*[.-]$qualifier[.\\d-+]*") }
        .any { it.matches(version) }

tasks.withType<DependencyUpdatesTask> {
    rejectVersionIf {
        isNonStable(candidate.version)
    }
}

tasks.named<DependencyUpdatesTask>("dependencyUpdates").configure {
    checkForGradleUpdate = true
    outputFormatter = "json"
    outputDir = "build/dependencyUpdates"
    reportfileName = "report"
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])

            pom {
                name.set("trilead-ssh2")
                description.set("The SSH library formerly used by the ConnectBot app (DEPRECATED)")
                url.set(gitHubUrl)
                licenses {
                    license {
                        name.set("BSD 3-Clause License")
                        url.set("https://opensource.org/licenses/BSD-3-Clause")
                    }
                }
                developers {
                    developer {
                        name.set("Kenny Root")
                        email.set("kenny@the-b.org")
                    }
                }
                scm {
                    connection.set("$gitHubUrl.git")
                    developerConnection.set("$gitHubUrl.git")
                    url.set(gitHubUrl)
                }
            }
        }
    }
}

signing {
    setRequired({
        gradle.taskGraph.hasTask("publish")
    })
    sign(publishing.publications["mavenJava"])
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://ossrh-staging-api.central.sonatype.com/service/local/"))
            snapshotRepositoryUrl.set(uri("https://central.sonatype.com/repository/maven-snapshots/"))
        }
    }
}
