package main



apt_commands = [
	"apt-get upgrade",
	"dist-upgrade",
]

denylist = [
  "openjdk"
]

deny[msg] {
  input[i].Cmd == "from"
  val := input[i].Value
  contains(val[i], denylist[_])

  msg = sprintf("unallowed image found %s", [val])
}


deny [msg] {
	input[i].Cmd == "from"
	val := input[i].Value
	endswith(val[i], ":latest")

	msg = sprintf("Please don't use the latest tags. Ensure you identity the version which you've tested with %v", [val])

}

warn [msg] {
	input[i].Cmd == "run"
	val := concat(" ", input[i].Value)
	contains(lower(val), apt_commands[_])

	msg = sprintf("Please don't use %v. Most dependencies are unlikely to installl inside an unprivileged container. Use apt-get install -y foo instead", [val])
}