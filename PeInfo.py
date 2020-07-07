# -*- coding: UTF-8 -*_
import os
import lief
import sys
from optparse import OptionParser

def AnalysisFile(inputfile, outputfile):
	# test
	#print(inputfile)
	#print(outputfile)

	binary = lief.parse(inputfile)
	if not binary:
		print('can\'t parse: ' + inputfile)
		return
	f = open(outputfile, 'w', encoding='utf-8')

	print('== Imports ==', file=f);
	imports = binary.imports
	for import_ in imports:
		import_ = lief.PE.resolve_ordinals(import_)

		print('  {}'.format(import_.name), file=f)
		entries = import_.entries
		for entry in entries:
			print("    {}".format(entry.name), file=f)

	print('', file=f)
	print("== Exports ==", file=f)
	exports = binary.get_export()
	entries = exports.entries
	entries = sorted(entries, key=lambda e : e.ordinal)
	for entry in entries:
		print("  {}".format(entry.name), file=f)


def AnalysisDir(inputdir):
	if inputdir[-1] == '\\':
		dirFatherPath, dirname = os.path.split(inputdir[:-1])
	else:
		dirFatherPath, dirname = os.path.split(inputdir)

	fatherLen = len(dirFatherPath)
	print(dirFatherPath)
	print('.' + inputdir[fatherLen:])
	print('')
	os.makedirs('.' + inputdir[fatherLen:])

	for root, dirs, files in os.walk(inputdir):
		for f in files:
			fileOldPath = os.path.join(root, f)
			fileNewPath = '.' + os.path.splitext(fileOldPath)[0][fatherLen:] + '.log'

			#test
			print(fileOldPath)
			print(fileNewPath)
			print('')
			AnalysisFile(fileOldPath, fileNewPath)

		for d in dirs:
			subDirPath = os.path.join('.' + root[fatherLen:], d)
			os.makedirs(os.path.join('.' + root[fatherLen:], d))


def main():
    optparser = OptionParser(
            usage='Usage: %prog [options] <pe-file>',
            add_help_option = True,
            prog=sys.argv[0])

    optparser.add_option('-t', '--target file',
    		action='store', dest='analysis_file',
    		help='Analysis of a specified pe file')

    optparser.add_option('-T', '--target dir',
    		action='store', dest='analysis_directory',
    		help='Analysis of a specified directory')

    options, left_args = optparser.parse_args()

    # test
    print(options.analysis_file)
    print(options.analysis_directory)   


    if options.analysis_file:
    	filepath, filename = os.path.split(options.analysis_file)
    	logname = os.path.splitext(filename)[0]
    	logpath = filepath + '\\' + logname + '.log'

    	#test
    	#print(logpath)
    	AnalysisFile(options.analysis_file, logpath)

    if options.analysis_directory:
    	AnalysisDir(options.analysis_directory)




if __name__ == "__main__":
    main()