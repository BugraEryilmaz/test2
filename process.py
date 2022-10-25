infile = open('./in.txt')
outfile = open('./out.txt', 'w')

for line in infile:
    if line.rstrip().isnumeric() is True:
        outfile.write(line)
infile.close()
outfile.close()
