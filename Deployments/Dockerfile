FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y golang && apt-get install -y ca-certificates && apt-get install -y nmap


WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main cmd/scanner/main.go

#COPY --from=builder /app/main .
#COPY --from=builder /app/*.nmap ./  # Example if you have additional nmap files

EXPOSE 9000

CMD ["./main"]
