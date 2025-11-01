# King_bless-hacking-multi-tool-
# Update Termux
pkg update && pkg upgrade -y

# Install Python and required packages
pkg install python -y
pkg install libxml2 libxslt -y

# Install Python modules
pip install requests colorama dnspython urllib3

# Run KING BLESS
python king_bless.py
