# vuln-sim

![alt text](https://github.com/blackducksoftware/vuln-sim/raw/master/vulnsim.png
 "a vulnerabilities vs remediation simulator")


## To run a simulation

Look at the code in main.go, the parameters are self-explanatory.

## Go

just export your gopath
cd clustersim/
go run main.go

Hack around with the simulation settings as needed and re run.

The graphs will pop up in your terminal !


## DOCKER 

Then, you can build and run: 

`docker build -t jayunit100/vuln-sim:latest ./ ; docker run -t -i jayunit100/vuln-sim:latest`

The structs in main.go (RegistrySize, ScansPerMinute, SimTime) parameters can be modified.

This is Apache Licensed Software.

If you don't know what that means, you shouldn't be using it.
