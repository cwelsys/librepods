
import java.util.Properties

val props = Properties().apply {
    rootProject.file("version.properties").inputStream().use(::load)
}

val major = props.getProperty("major").toInt()
val minor = props.getProperty("minor").toInt()
val patch = props.getProperty("patch").toInt()
val stage = props.getProperty("stage").toString()
val buildNumber = props.getProperty("build").toInt()

val stageCodes = mapOf(
    "alpha" to 0,
    "beta" to 1,
    "rc" to 2,
    "stable" to 3
)

require(major in 0..99)
require(minor in 0..99)
require(patch in 0..99)
require(stage in stageCodes)
require(buildNumber in 1..99)

val appVersionName = "$major.$minor.$patch" +
    if (stage == "stable") "" else "-$stage.$buildNumber"

// [M][mm][pp][s][bb]
val appVersionCode = (
    major.toLong() * 100_000_000 +
    minor * 1_000_000 +
    patch * 10_000 +
    stageCodes.getValue(stage) * 100 +
    buildNumber
    ).also {
        require(it in 1..2_100_000_000L) {
            "versionCode exceeds Android's maximum"
        }
    }.toInt()

extensions.extraProperties["appVersionName"] = appVersionName
extensions.extraProperties["appVersionCode"] = appVersionCode

tasks.register("printAppVersion") {
    description = "Prints the current app version."

    val name = appVersionName
    val code = appVersionCode

    doLast {
        println("VERSION_NAME=$name")
        println("VERSION_CODE=$code")
    }
}

