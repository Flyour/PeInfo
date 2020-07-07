# -*- coding: UTF-8 -*_
import json
import os
import lief
import sys
from optparse import OptionParser

def AnalysisFile(inputfile, outputfile):
	log = {}
	importmodule= {}

	binary = lief.parse(inputfile)
	if not binary:
		print('can\'t parse: ' + inputfile)
		return
	f = open(outputfile, 'w', encoding='utf-8')

	imports = binary.imports
	for import_ in imports:
		import_ = lief.PE.resolve_ordinals(import_)

		modulename = import_.name
		importFuncs = []

		entries = import_.entries
		for entry in entries:
			importFuncs.append(entry.name)

		importmodule[modulename] = importFuncs
	log['Imports'] = importmodule 

	exportFuncs = []
	exports = binary.get_export()
	entries = exports.entries
	entries = sorted(entries, key=lambda e : e.ordinal)
	for entry in entries:
		exportFuncs.append(entry.name)
	log['Exports'] = exportFuncs

	f.write(json.dumps(log, indent=4))
	f.close()


def AnalysisDir(inputdir):
	if inputdir[-1] == '\\':
		dirFatherPath, dirname = os.path.split(inputdir[:-1])
	else:
		dirFatherPath, dirname = os.path.split(inputdir)

	fatherLen = len(dirFatherPath)
	os.makedirs('.' + inputdir[fatherLen:])

	for root, dirs, files in os.walk(inputdir):
		for f in files:
			fileOldPath = os.path.join(root, f)
			fileNewPath = '.' + os.path.splitext(fileOldPath)[0][fatherLen:] + '.json'

			#test
			print('')
			print(fileOldPath)
			print(fileNewPath)
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

    # 对单个文件进行分析
    if options.analysis_file:
    	filepath, filename = os.path.split(options.analysis_file)
    	logname = os.path.splitext(filename)[0]
    	logpath = filepath + '\\' + logname + '.json'
    	AnalysisFile(options.analysis_file, logpath)

    # 对目标文件夹进行分析
    if options.analysis_directory:
    	AnalysisDir(options.analysis_directory)


if __name__ == "__main__":
    main()
