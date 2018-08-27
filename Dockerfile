FROM golang:1.9

WORKDIR /go/src/github.com/blackducksoftware/vuln-sim/

COPY . .

RUN pwd
RUN pwd
RUN ls -altrh 

WORKDIR /go/src/github.com/blackducksoftware/vuln-sim/clustersim

RUN go build ./
RUN chmod 777 clustersim
RUN ls -altrh ./

CMD /bin/sh

