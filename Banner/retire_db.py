import json
import re
from pathlib import Path


VERSION_CAPTURE = r"([0-9A-Za-z._+\-]+)"


class RetireDB:

    def __init__(self, db_path="data/jsrepository-v6-combined.json"):

        self.filename_index = {}
        self.content_index = {}

        self.db_path = Path(db_path)

        self.database = {}

        self.filename_patterns = []
        self.filecontent_patterns = []
        self.hashes = {}

        self.load_database()

    def load_database(self):

        with open(self.db_path, encoding="utf-8") as f:
            self.database = json.load(f)

        self.build_indexes()

    def extract_keyword(self, pattern):
        """
        Guess the library keyword from a Retire.js regex.
        """
        pattern = pattern.lower()
    # Remove escape characters
        pattern = pattern.replace("\\", "")
        m = re.search(r"[a-z][a-z0-9._-]{2,}", pattern)
        if m:
            return m.group(0)
        return None

    def compile_pattern(self, pattern):

        pattern = pattern.replace(
            "§§version§§",
            VERSION_CAPTURE
        )
        try:
            return re.compile(pattern, re.I)
        except re.error:
            return None


    def build_indexes(self, pattern):


        for library, data in self.database.items():
            
            extractors = data.get("extractors", {})
            for pattern in extractors.get("filename", []):
                regex = self.compile_pattern(pattern)
                keyword = self.extract_keyword(pattern)

                entry = {
                "library": library,
                "regex": regex,
                "vulnerabilities": data.get("vulnerabilities", [])
                }
                self.filename_patterns.append(entry)
                if keyword:
                    self.filename_index.setdefault(keyword, []).append(entry)
            
                '''if regex:
                    self.filename_patterns.append({
                        "library": library,
                        "regex": regex,
                        "vulnerabilities":
                            data.get("vulnerabilities", [])
                    })'''
                
            ##################################
            # filecontent
            ##################################

            for pattern in extractors.get("filecontent", []):
                regex = self.compile_pattern(pattern)
                keyword = self.extract_keyword(pattern)

                entry = {
                    "library": library,
                    "regex": regex,
                    "vulnerabilities": data.get("vulnerabilities", [])
                }

                self.filecontent_patterns.append(entry)

                if keyword:
                    self.content_index.setdefault(keyword, []).append(entry)

                ''''if regex:
                    self.filecontent_patterns.append({
                        "library": library,
                        "regex": regex,
                        "vulnerabilities":
                            data.get("vulnerabilities", [])
                    })''''
            ##################################
            # hashes
            ##################################
            hashes = extractors.get("hashes", {})
            for sha, version in hashes.items():
                self.hashes[sha.lower()] = {
                    "library": library,
                    "version": version,
                    "vulnerabilities":
                        data.get("vulnerabilities", [])
                }

    ############################################

    def match_filename(self, filename):

        filename = filename.lower()

        candidate_patterns = []

        for keyword, patterns in self.filename_index.items():
            if keyword in filename:
                candidate_patterns.extend(patterns)

        if not candidate_patterns:
            candidate_patterns = self.filename_patterns

        for item in candidate_patterns:
            m = item["regex"].search(filename)
            if m:
                return {
                "library": item["library"],
                "version": m.group(1) if m.lastindex else None,
                "vulnerabilities": item["vulnerabilities"]
            }

        '''for item in self.filename_patterns:
            m = item["regex"].search(filename)
            if m:
                version = None
                if m.lastindex:
                    version = m.group(1)
                return {
                    "library": item["library"],
                    "version": version,
                    "vulnerabilities":
                        item["vulnerabilities"]
                }
        return None'''

    ############################################

    def match_content(self, text):

        candidate_patterns = []
        text_lower = text.lower()

        for keyword, patterns in self.content_index.items():
            if keyword in text_lower:
                candidate_patterns.extend(patterns)

        if not candidate_patterns:
            candidate_patterns = self.filecontent_patterns

        for item in candidate_patterns:
            m = item["regex"].search(text)
            if m:
                return {
                "library": item["library"],
                "version": m.group(1) if m.lastindex else None,
                "vulnerabilities": item["vulnerabilities"]
            }


        '''for item in self.filecontent_patterns:
            m = item["regex"].search(text)
            if m:
                version = None
                if m.lastindex:
                    version = m.group(1)
                return {
                    "library": item["library"],
                    "version": version,
                    "vulnerabilities":
                        item["vulnerabilities"]
                }
        return None'''

    ############################################

    def match_hash(self, sha):

        return self.hashes.get(sha.lower())

    ############################################

    def stats(self):

        return {

            "libraries":
                len(self.database),

            "filename_patterns":
                len(self.filename_patterns),

            "filecontent_patterns":
                len(self.filecontent_patterns),

            "hashes":
                len(self.hashes)

        }