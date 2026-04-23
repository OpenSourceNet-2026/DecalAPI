DecalAPI is a small, easy-to-use tool that lets you check file hashes using VirusTotal. It's kind off look like a browser on search so, SEARCH function for all your reports, just don't forget to get a separate virustotal account. Uses .env for securing your api and keys.

Here are some things it can do:
You can use it to look up MD5, SHA1, or SHA256 hashes through VirusTotal's latest API.
It also grabs extra details like tags and signatures from MalwareBazaar.
If you have an any.run Hunter plan, you can also get a sandbox report.
All your scan results are saved on your computer, so they'll still be there even if you close and reopen the program.
There's a cool feature to create custom comments for VirusTotal, using placeholders for things like the hash or tags.
It's designed to look like a standard Windows app, using the Segoe UI font and colors that feel familiar.

Getting it set up is pretty straightforward. First, you'll want to grab the code from GitHub. After that, navigate into the DecalAPI folder, install all the necessary bits, and then run the main program.

When you open it for the first time, head over to the Settings, that's the little gear icon in the top-right corner and put in your VirusTotal API key there. Another way to do it is to take the .env.example file, rename it to .env, and then type your keys directly into that file.

Here's a quick rundown of the API keys you might need:
You definitely need a VirusTotal API key you can find it in your profile on virustotal.com
For MalwareBazaar, an API key is required.
And if you want to use the any.run features, you'll need an API key from there, but only if you have their Hunter plan.

You can set up your own comment template under Settings, specifically in the "Average VirusTotal Comment" section. When you run a scan, the program will automatically swap out these special placeholders with the actual info:
{HASH} will be replaced with the hash you just scanned.
{tags} will show all the tags collected from VirusTotal, MalwareBazaar, and any.run.
{detections} tells you how many engines flagged the file as malicious or suspicious.
{total} is the total number of engines that checked the file.
{date} simply gives you today's date.
{names} lists up to five common filenames for that hash from VirusTotal.
{family} will show the main malware family, if VirusTotal identifies one.
{verdict} provides the sandbox verdict from any.run.

By default, the template looks like this:
CHANGE ME
{HASH}
Detected by DecalAPI
Common tags: {tags}

If you're curious about how the project is put together, here's a quick look at the main files and what they do:
main.py is where the program starts.
requirements.txt lists everything you need to install.
.env.example is a sample file for your API keys, you'll copy it to .env.
and the rest does the rest.
anyrun_fetch | obviously fetchs it
comment_gen | for comments generations
config_store | your config are stored locally
and more etc.
Thanks for supporting this project, if you have further questions or you want to donate please kindly discuss it on Github Discussions and i will give a link. Or else if you want it privately just head to https://dev.to/osncs
This project is under the MIT License, which basically means you're free to use, change, and share it however you like.