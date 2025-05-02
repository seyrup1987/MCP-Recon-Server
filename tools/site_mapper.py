import requests as rq
from bs4 import BeautifulSoup
from icecream import ic
from tqdm import tqdm
from urllib.parse import urlparse, urljoin
import Valid_Proxy_Servers as vps
import argparse
import random
import json
import os

visited_links = []
Proxy_Server_List = []
bad_URLs = []
PROXY_LIST_PATH = os.path.join("..", "config", "proxy_list.txt")

def output_to_file(text):
    with open('site_mapper_debug_log.txt', 'a', encoding='utf-8') as f:
        f.write(text+'\n')

def site_mapper(URL: str):
	server = ic(random.choice(Proxy_Server_List))
	for link in tqdm(visited_links):
		if URL == link:
			return
	response = ic(rq.get(URL))
	if response.status_code == 200:
		print("sitae page ", URL, "is valid")

		soup = BeautifulSoup(response.content, 'html.parser')
		tag = soup.find_all("a")

		URL_Components = ic(urlparse(URL))
		scheme = URL_Components.scheme
		netloc = URL_Components.netloc
		links_on_page = []
		print("Parsing links in ",URL)
		for entry in tag:
			t = entry.get('href')
			link_components = urlparse(t)
			if link_components.scheme == '' and link_components.netloc == '':
				temp = urljoin(URL, t)
				t = temp
			links_on_page.append(t)
		
		ic(visited_links.append(URL))

		print("Visiting links in ",URL)
		visiting_links = []
		for link in links_on_page:
			link_components = urlparse(link)
			if link_components.scheme == scheme and link_components.netloc == netloc:
				ic(visiting_links.append(link))

		for link in visited_links:
			for an_link in visiting_links:
				if link == an_link:
					continue
				else:
					site_mapper(an_link)
			return
	else:
		print("\n",URL," is invalid\nHTTPErrorCode: ", response.status_code,"\n")
		ic(visited_links.append(URL))
		ic(bad_URLs.append(URL))
		return 
	return {visited_links, bad_URLs}

if __name__ == '__main__':
	ic.configureOutput(prefix='Debug | ', outputFunction=output_to_file, includeContext=True)
	
	parser = argparse.ArgumentParser(description="Mapping all the pages of a given website")
	parser.add_argument("URL", help="URL  of the website, which will be mapped", type=str)
	args = parser.parse_args()
	URL = args.URL

	# Proxy_Server_List = ic(vps.get_proxy_servers())
	# print("List of valid Proxy Servers are: ", Proxy_Server_List)

	visit, invalid = site_mapper(URL)

	print("The list of Visited pages are: ")
	for entry in visited_links:
		print("\n",entry,"\n")

	components = urlparse(URL)

	Output_Object_JOSN = {"website": components.netloc,
							"pages": visited_links,
							"invalid_URLS": invalid}

	working_directory = os.getcwd()
	output_path = ic(os.path.join(working_directory, 'Output'))
	output_file = ic(os.path.join(output_path, components.netloc+'_sitemap.json'))

	if not os.path.exists(output_path):
		os.popen("mkdir "+output_path)

	with open(output_file, 'a') as file:
		json.dump(Output_Object_JOSN, file)
