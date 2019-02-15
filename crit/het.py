import os
import json
import sys
import pycriu
import shutil
import tempfile
from collections import OrderedDict
from ctypes import *
from shutil import copyfile
from pwnlib.elf.elf import ELF

PAGE_SIZE=4096

class Regs(Structure):
	_fields_ = [("x", c_ulonglong)]
class VRegs(Structure):
	_fields_ = [("x", c_ulonglong), ("y", c_ulonglong)]
class Aarch64Struct(Structure):
	_fields_ = [("magic", c_ulonglong), ("sp", c_ulonglong), ("pc", c_ulonglong), ("regs", Regs * 31), ("vregs", VRegs * 32)]
class X86Struct(Structure):
	pass #TODO

def get_symbol_addr(binary, symbol):
	###find address of the structure
	e = ELF(binary)
	addr=long(e.symbols[symbol]) 
	print "found address", hex(addr)
	return addr

def __load_file(file_path):
	try:
		pgm_img = pycriu.images.load(open(file_path, 'rb'), pretty=True)
	except pycriu.images.MagicException as exc:
		print("Error reading", file_path)
		sys.exit(1)
	return pgm_img

def get_pages_offset(addr, pagemap_file):
	###find the offset size of the structure in pages_file using pagemap_file
	#find offset, size? (168?)
	pgm_img=__load_file(pagemap_file)
	page_number=0
	region_offset=-1
	for dc in  pgm_img['entries']:
		if 'vaddr' in dc.keys():
			base = long(dc['vaddr'], 16)
			pnbr = dc['nr_pages']
			end = base+(pnbr*PAGE_SIZE)
			print "current region", hex(base), hex(end), pnbr
			if addr>=base and addr<end:
				region_offset=(addr-base)
				region_offset+=(page_number*PAGE_SIZE)
				print "found in region", hex(base), hex(addr), hex(end)
				print "page offset",  region_offset
				break
			page_number+=pnbr

	return region_offset

def read_struct_from_pages(pages_file, region_offset):
	#read at correcpoding offset
	fd=open(pages_file, 'rb')
	fd.seek(region_offset)
	#print fd.tell()
	dest_regs = Aarch64Struct()

	#print "reading", fd.read(-1) 
	#return
	ret=fd.readinto(dest_regs) 
	print "size", sizeof(dest_regs), "ret", ret
	print "magic", hex(dest_regs.magic)
	print "pc", dest_regs.pc
	print "sp", dest_regs.sp
	for reg in dest_regs.regs:
		pass #print reg.x
	for reg in dest_regs.vregs:
		pass #print reg.x, reg.y
	return dest_regs

def read_llong_from_pages(pages_file, region_offset):
	#read at correcpoding offset
	fd=open(pages_file, 'rb')
	fd.seek(region_offset)
	dest_reg = Regs()
	ret=fd.readinto(dest_reg) 
	return dest_reg.x


def read_regs_from_memory(binary, architecture, pagemap_file, pages_file):
	addr=get_symbol_addr(binary, 'regs_dst')

	region_offset=get_pages_offset(addr, pagemap_file)
	if(region_offset==-1):
		print "addr region not found"
		return

	return read_struct_from_pages(pages_file, region_offset)

def read_tls_from_memory(binary, architecture, pagemap_file, pages_file):
	addr=get_symbol_addr(binary, 'tls_dst')

	region_offset=get_pages_offset(addr, pagemap_file)
	if(region_offset==-1):
		print "addr region not found"
		return

	tls_addr=read_llong_from_pages(pages_file, region_offset)
	print "tls_base", hex(tls_addr)
	return tls_addr


def get_src_core(core_file):
	pgm_img=__load_file(core_file)
	#print(pgm_img['entries'][0]['mtype'])
	#print(pgm_img['entries'][0]['thread_info'])
	return pgm_img

def get_rlimits():
	return [ {
                            "cur": 18446744073709551615, 
                            "max": 18446744073709551615
                        }, 
                        {
                            "cur": 18446744073709551615, 
                            "max": 18446744073709551615
                        }, 
                        {
                            "cur": 18446744073709551615, 
                            "max": 18446744073709551615
                        }, 
                        {
                            "cur": 8388608, 
                            "max": 18446744073709551615
                        }, 
                        {
                            "cur": 0, 
                            "max": 18446744073709551615
                        }, 
                        {
                            "cur": 18446744073709551615, 
                            "max": 18446744073709551615
                        }, 
                        {
                            "cur": 515331, 
                            "max": 515331
                        }, 
                        {
                            "cur": 1024, 
                            "max": 1048576
                        }, 
                        {
                            "cur": 18446744073709551615, 
                            "max": 18446744073709551615
                        }, 
                        {
                            "cur": 18446744073709551615, 
                            "max": 18446744073709551615
                        }, 
                        {
                            "cur": 18446744073709551615, 
                            "max": 18446744073709551615
                        }, 
                        {
                            "cur": 515331, 
                            "max": 515331
                        }, 
                        {
                            "cur": 819200, 
                            "max": 819200
                        }, 
                        {
                            "cur": 0, 
                            "max": 0
                        }, 
                        {
                            "cur": 0, 
                            "max": 0
                        }, 
                        {
                            "cur": 18446744073709551615, 
                            "max": 18446744073709551615
                        }
                    ]

	
def convert_to_dest_core(pgm_img, dest_regs, dest_tls):
	#pgm_img=__load_file(core_file)
	###convert the type
	pgm_img['entries'][0]['mtype']="AARCH64"

	###convert thread_info
	src_info=pgm_img['entries'][0]['thread_info']
	dst_info=OrderedDict() 
	dst_info["clear_tid_addr"]=src_info["clear_tid_addr"]
	dst_info["tls"]=dest_tls
	##gpregs
	dst_info["gpregs"]=OrderedDict()
	#regs
	reg_list=list()
	for reg in dest_regs.regs:
		reg_list.append(hex(reg.x))
	dst_info["gpregs"]["regs"]=reg_list
	#sp, pc, pstate
	dst_info["gpregs"]["sp"]=dest_regs.sp
	dst_info["gpregs"]["pc"]=dest_regs.pc
	dst_info["gpregs"]["pstate"]="0x60000000" #?
	##fpsimd
	dst_info["fpsimd"]=OrderedDict()
	vreg_list=list()
	for vreg in dest_regs.vregs:
		#FIXME:check order
		vreg_list.append(hex(vreg.x))
		vreg_list.append(hex(vreg.y))
	dst_info["fpsimd"]["vregs"]=vreg_list
	dst_info["fpsimd"]["fpsr"]=0 #?
	dst_info["fpsimd"]["fpcr"]=0 #?
	

	#delete old entry and add the new one
	del pgm_img['entries'][0]['thread_info']
	pgm_img['entries'][0]['ti_aarch64'] = dst_info

	#convert tc
	pgm_img['entries'][0]['tc']['cg_set'] = 1
	pgm_img['entries'][0]['tc']['loginuid'] = 1004
	pgm_img['entries'][0]['tc']['rlimits']["rlimits"] = get_rlimits()
	pgm_img['entries'][0]['thread_core']['creds']['uid'] = 1004
	pgm_img['entries'][0]['thread_core']['creds']['euid'] = 1004
	pgm_img['entries'][0]['thread_core']['creds']['suid'] = 1004
	pgm_img['entries'][0]['thread_core']['creds']['fsuid'] = 1004
	

	return pgm_img
	
def get_target_core(architecture, binary, pages_file, pagemap_file, core_file):
	dest_regs=read_regs_from_memory(binary, architecture, pagemap_file, pages_file)
	dest_tls=read_tls_from_memory(binary, architecture, pagemap_file, pages_file)
	src_core=get_src_core(core_file)
	dst_core=convert_to_dest_core(src_core, dest_regs, dest_tls)
	return dst_core

def get_binary(files_path):
	pgm_img=__load_file(files_path)
	return pgm_img["entries"][0]["reg"]["name"]

def get_target_files(files_path):
	pgm_img=__load_file(files_path)
	path=pgm_img["entries"][0]["reg"]["name"]
	path_x86_64=path+"_x86-64"
	path_aarch64=path+"_aarch64"
	assert(os.path.isfile(path_x86_64) and os.path.isfile(path_aarch64))
	#copy file to appropriate arch
	copyfile(path_aarch64, path)
	#set size
	statinfo = os.stat(path)
	pgm_img["entries"][0]["reg"]["size"] = statinfo.st_size
	#hack: create tmp file; update: on target machine!!
	#open("/tmp/stack-transform.log", 'a').close()

	return pgm_img

def __get_tmp_copy(src_file):
	f=tempfile.TemporaryFile()
	shutil.copy(src_file, f.name)
	return f

def remove_region_type(mm_img, pagemap_img, page_tmp, region_type):
	region_start=-1
	region_end=-1
	#get address and remove vma
	idx=0
	for vma in mm_img["entries"][0]["vmas"][:]:
		if region_type in vma["status"]:
                	region_start=int(vma["start"], 16)
                	region_end=int(vma["end"], 16)
			print("removing vma",mm_img["entries"][0]["vmas"][idx])
			del mm_img["entries"][0]["vmas"][idx]
			break
		idx+=1
	assert(region_start!=-1)
	print(hex(region_start), hex(region_end))
	
	#pagemap
	idx=0
	page_offset=-1
	page_start_nbr=0
	page_nbr=-1
	for pgmap in pagemap_img["entries"][:]:
		if "vaddr" not in pgmap.keys():
			idx+=1
			continue
		addr=int(pgmap["vaddr"], 16)
		page_nbr = pgmap['nr_pages']
		if addr >= region_start and addr <= region_end:
			print("removing pagemap", pagemap_img["entries"][idx])
			del pagemap_img["entries"][idx]
			break
		idx+=1
		page_start_nbr+=page_nbr
	assert(page_nbr!=-1)

	page_offset=page_start_nbr*PAGE_SIZE
	page_offset_end=page_offset+(page_nbr*PAGE_SIZE)
	total_size=os.stat(page_tmp.name).st_size

	#truncate page_tmp from page_offset to page_offset_end
	page_tmp.seek(page_offset_end)
	buff=page_tmp.read(total_size-page_offset_end)

	page_tmp.seek(page_offset)
	page_tmp.write(buff) #total_size-page_offset_end

	page_tmp.truncate(total_size-(page_offset_end-page_offset))

	return

def __get_vvar_template(region_type):
	mm={ "start": "0xffffacaa5000", 
                    "end": "0xffffacaa6000", 
                    "pgoff": 0, 
                    "shmid": 0, 
                    "prot": "PROT_READ", 
                    "flags": "MAP_PRIVATE | MAP_ANON", 
                    "status": "VMA_AREA_REGULAR | VMA_ANON_PRIVATE | VMA_AREA_VVAR", 
                    "fd": -1}

	return mm, None, None

def __get_vdso_template(region_type):
	mm= { "start": "0xffffacaa6000", 
                    "end": "0xffffacaa7000", 
                    "pgoff": 0, 
                    "shmid": 0, 
                    "prot": "PROT_READ | PROT_EXEC", 
                    "flags": "MAP_PRIVATE | MAP_ANON", 
                    "status": "VMA_AREA_REGULAR | VMA_AREA_VDSO | VMA_ANON_PRIVATE", 
                    "fd": -1
                } 
	pgmap={"vaddr": "0xffffacaa6000", 
            "nr_pages": 1, 
            "flags": "PE_PRESENT"}
	dir_path=os.path.dirname(os.path.realpath(__file__))
	vdso_path=os.path.join(dir_path, "templates/", "arm_vdso.img")
	f=open(vdso_path, "rb")
	vdso=f.read(PAGE_SIZE)
	f.close()

	return mm, pgmap, vdso
	
def get_target_template(region_type):
	if "VDSO" in region_type:
		return __get_vdso_template(region_type)
	if "VVAR" in region_type:
		return __get_vvar_template(region_type)

def add_target_region(mm_img, pagemap_img, page_tmp, region_type):
	mm_tmpl, pgmap_tmpl, cnt_tmpl = get_target_template(region_type)

	#insert_vma
	region_start=int(mm_tmpl["start"], 16)
	region_end=int(mm_tmpl["end"], 16)
	vmas=mm_img["entries"][0]["vmas"]
	idx=0
	for vma in vmas:
                vma_start=int(vma["start"], 16)
                vma_end=int(vma["end"], 16)
		if vma_start >= region_end:
			#we need to insert before this region
			#check that we don't overlap with prev
			if(idx>0):
				prev_vma=mm_img["entries"][0]["vmas"][idx-1]
				pvend=int(prev_vma["end"],16)
				if(pvend > region_start):
					print("error: could not insert region", hex(vma_start), hex(vma_end), hex(region_start), hex(region_end), hex(pvend))
					return
			break
		idx+=1
	print("found vma at idx", idx, len(vmas))
	mm_img["entries"][0]["vmas"]=vmas[:idx]+[mm_tmpl]+vmas[idx:]

	#insert pgmap if any
	if not pgmap_tmpl:
		return
	#pagemap
	idx=0
	page_offset=-1
	page_start_nbr=0
	page_nbr=-1
	target_vaddr=int(pgmap_tmpl["vaddr"], 16)
	target_nbr=pgmap_tmpl["nr_pages"]
	pages_list=pagemap_img["entries"]
	for pgmap in pages_list:
		#FIXME: handle case first entry
		if "vaddr" not in pgmap.keys():
			idx+=1
			continue
		addr=int(pgmap["vaddr"], 16)
		page_nbr = pgmap['nr_pages']
		addr_end=addr+(page_nbr*PAGE_SIZE)
		if addr >= target_vaddr:
			print("pagemap found spot")
			#insert before this regions
			break
		idx+=1
		page_start_nbr+=page_nbr
	print("found page at idx", idx, len(pages_list))
	print("found page at idx", pgmap_tmpl , pages_list[idx:])
	assert(page_nbr!=-1)
	pagemap_img["entries"]=pages_list[:idx]+[pgmap_tmpl]+pages_list[idx:]
	#where to insert in pages
	page_offset=page_start_nbr*PAGE_SIZE+(page_nbr*PAGE_SIZE)
	buff_size=(target_nbr*PAGE_SIZE)

	#insert in pages
	total_size=os.stat(page_tmp.name).st_size
	page_tmp.seek(page_offset)
	buff=page_tmp.read(total_size-page_offset)
	
	page_tmp.seek(page_offset)
	assert(buff_size == len(cnt_tmpl))
	page_tmp.write(cnt_tmpl)#, buff_size)
	page_tmp.write(buff) #, total_size-page_offset_end)

	return
	

def get_target_mem(mm_file, pagemap_file,  pages_file):
	mm_img=__load_file(mm_file)
	pagemap_img=__load_file(pagemap_file)
	pages_tmp=__get_tmp_copy(pages_file)
	remove_region_type(mm_img, pagemap_img, pages_tmp, "VDSO")
	remove_region_type(mm_img, pagemap_img, pages_tmp, "VVAR")
	remove_region_type(mm_img, pagemap_img, pages_tmp, "VSYSCALL")
	add_target_region(mm_img, pagemap_img, pages_tmp, "VDSO")
	add_target_region(mm_img, pagemap_img, pages_tmp, "VVAR")
	return mm_img, pagemap_img, pages_tmp.name

def test_convert_core():
	pid=3614
	binary="/share/karaoui/criu-project/popcorn-compiler/tests/hello/test"
	pages_file="/share/karaoui/criu-project/dumps/hello/new-dump/pages-1.img"
	pagemap_file="/share/karaoui/criu-project/dumps/hello/new-dump/pagemap-"+str(pid)+".img"
	core_file="/share/karaoui/criu-project/dumps/hello/new-dump/core-"+str(pid)+".img"
	architecture=1
	dst_core=get_target_core(architecture, binary, pages_file, pagemap_file, core_file)
	#f = open("new_core."+str(architecture), "w+")
	f = sys.stdin
	json.dump(dst_core, f, indent=4)
	if f == sys.stdout:
		f.write("\n")

if __name__ == '__main__':
	test_convert_core()
