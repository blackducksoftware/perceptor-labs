# vuln-sim

## To run a simulation

Look at the code in main.go, the parameters are self-explanatory.


Then, you can build and run: 

`docker build -t jayunit100/vuln-sim:latest ./ ; docker run -t -i jayunit100/vuln-sim:latest`

The structs in main.go (RegistrySize, ScansPerMinute, SimTime) parameters can be modified.

This is Apache Licensed Software.

If you don't know what that means, you shouldn't be using it.
