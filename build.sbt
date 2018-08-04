name := "gitbucket-oauth2-plugin"
organization := "tak.github.gitbucket"
version := "1.0.0"
scalaVersion := "2.12.6"
gitbucketVersion := "4.25.0"

lazy val root = (project in file(".")).enablePlugins(SbtTwirl)

libraryDependencies ++= Seq(
  "io.github.gitbucket" %% "gitbucket"          % "4.25.0" % "provided",
  "com.typesafe.play"   %% "twirl-compiler"     % "1.3.0"  % "provided",
  "javax.servlet"        % "javax.servlet-api"  % "3.1.0"  % "provided"
)

scalacOptions := Seq("-deprecation", "-feature", "-language:postfixOps", "-Ydelambdafy:method", "-target:jvm-1.8")
javacOptions in compile ++= Seq("-target", "8", "-source", "8")

useJCenter := true
