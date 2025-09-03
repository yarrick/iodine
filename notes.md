# Run in Docker

## start server
```
sudo docker run --rm -it --name server --cap-add NET_ADMIN --device=/dev/net/tun -v $PWD/bin:/usr/local/bin --entrypoint /usr/local/sbin/iodined --network host iodine -f 10.0.0.1 test.com
```

## start client
```
sudo docker run --rm -it --name client --cap-add NET_ADMIN --device=/dev/net/tun -v $PWD/bin:/usr/local/bin --network host iodine iodine -f -r 128.140.113.217 test.com
```
replace 128.140.113.217 with server IP
