import ftplib

def ftp_connect():
    ftp = ftplib.FTP()
    ftp.connect('127.0.0.1', 2121)  # Connect to the proxy container
    ftp.login('user', 'pass')  # Login with the credentials for the FTP server
    print(ftp.getwelcome())
    ftp.quit()

if __name__ == "__main__":
    ftp_connect()