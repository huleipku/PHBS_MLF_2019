## Important Information:
* Due to restrictions with access to Google Safebrowsing API, please do not run mlurl.py with the -g (generate dataset) option during evaluation. The API only allows for a maximum of 10,000 requests per 24 hours. 
* Using mlurl.py with the -g option will take approximately between 2-3 hours due to feature extraction.
* mlurl.py -g can be used if you sign up to Google Cloud and use your own API key. 

## Install:
pip install -r requirements.txt

## Features:
* Analyses and Extracts features from URLs to determine if a file is malicious or not.
* Features include: Entropy, Bag Of Words, Contain IP address, URL Length, Special Characters, Suspicious Strings, Number Of Digits, Populatiry and Google Safebrowsing verdict.
* The selected features are both static and external.   
* Correlate results with Virus Total.

```
## Usage

### Train Model:
```
python mlurl.py -t
```
### Basic Usage:
```
python mlurl.py -c 'URL TO ANALYSE'
```
```
## Test Data:
The program is trained using malicious URLs and URLs that have specifically been linked to ransomware.

Test data for the program can be found here:
* https://openphish.com/feed.txt
* https://ransomwaretracker.abuse.ch/blocklist/
* https://www.phishtank.com/
