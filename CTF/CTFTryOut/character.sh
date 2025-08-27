# Create a sequence of numbers the exact length of the flag
# and pipe it to the netcat server (server responds with the characters 
# at those indexes) and save the output to a file
seq 0 103 | nc [IP] [PORT] -q 1 >> flag.txt

# The output looks like:
# Which character (index) of the flag do you want? Enter an index: Character at Index 0: H

# Initialize the flag variable as an empty string
flag=""

# Read the flag.txt file line by line and extract all characters of the flag
while IFS= read -r line; do
	char=$(echo $line | tail -c 2) 

	# Append each new character to the flag variable (H+T+B+{...)
	flag="$flag$char"
done < flag.txt

# Print the fully extracted flag
echo $flag
