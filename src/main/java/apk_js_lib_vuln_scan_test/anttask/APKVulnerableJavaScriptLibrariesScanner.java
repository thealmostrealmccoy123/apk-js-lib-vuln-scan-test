/**
 * Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package apk_js_lib_vuln_scan_test.anttask;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.taskdefs.MatchingTask;
import org.apache.tools.ant.types.Resource;

import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.JsVulnerability;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepository;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepositoryLoader;
import com.h3xstream.retirejs.util.HashUtil;

import apk_js_lib_vuln_scan_test.common.APKVulnerableJavaScriptFileLibraryList;
import apk_js_lib_vuln_scan_test.common.RetireJsVulnerabilitiesRepositoryLoader;

import org.apache.tools.ant.DirectoryScanner;
import org.apache.tools.ant.Project;

/**
 * Ant Task to scan APK files for vulnerable JavaScript libraries.
 * 
 * Uses @h3xstream retire.js burp extender core library.
 * https://github.com/h3xstream/burp-retire-js/tree/master/retirejs-core
 * 
 * @author arm
 *
 */
public class APKVulnerableJavaScriptLibrariesScanner extends MatchingTask {

    private String baseDirectory;
    
    private String includes;
    
    private String getInputStreamContentAsString(InputStream inputStream) {
        
        assert inputStream!=null;
        
        StringBuilder rawContent = null;

        try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {

            int c = bufferedReader.read();
            while (c != -1) {

                if (rawContent == null) {
                    rawContent = new StringBuilder();
                }
                rawContent.append((char) c);

                c = bufferedReader.read();
            }
            
        } catch (IOException e) {
            
            log(e, Project.MSG_ERR);

        }
        
        if (rawContent!=null) {

            return rawContent.toString();
            
        }
        
        return null;
    }
    
    private String[] splitAndTrim() {
        
        if ((getIncludes()!=null)) {
            
            String[] splitStrings = getIncludes().split(",");
            
            if ((splitStrings!=null)&&(splitStrings.length>0)) {
                
                for (int i=0; i<splitStrings.length; i++) {
                    
                    if (splitStrings[i]!=null) {
                        
                        splitStrings[i] = splitStrings[i].trim();
                    }
                }
                
                return splitStrings;
            }
            
        }
        
        return null;
    }
    
    private String getFullyQualifiedPath(String baseDirectory, Resource resource) {
        
        if ((baseDirectory!=null)&&(resource!=null)&&(resource.getName()!=null)) {
            
            return baseDirectory + "/" + resource.getName().replaceAll(Matcher.quoteReplacement("\\"), "/");
            
        }
        
        return null;
    }
    
    private VulnerabilitiesRepository getRetireJsVulnerabilitiesRepositoryData() {
    	
    	InputStream in = null;
    	
    	try {

            URL retireJsRepo = new URL(VulnerabilitiesRepositoryLoader.REPO_URL);
            
            URLConnection conn = retireJsRepo.openConnection();
            
            conn.connect();
            
            in = conn.getInputStream();
            
            RetireJsVulnerabilitiesRepositoryLoader vulnerabilitiesRepositoryLoader = new RetireJsVulnerabilitiesRepositoryLoader();
            
            VulnerabilitiesRepository vulnerabilitiesRepository = vulnerabilitiesRepositoryLoader.loadFromInputStream(in);
            
            in.close();
            
            return vulnerabilitiesRepository;
    		
    	} catch(IOException e) {
    		
    		log(e, Project.MSG_ERR);
    		
    	} finally {
    		
    		if (in!=null) {
    			
    			try {
    				
					in.close();
					
				} catch (IOException e) {
					
					log(e, Project.MSG_ERR);
					
				}
    		}
     		
    	}
    	
    	return null;
    }
    
    private void printVulnerabilitiesResult(List<JsLibraryResult> jsLibraryResultList, StringBuilder str) {
    	
		if ((jsLibraryResultList!=null)&&(!jsLibraryResultList.isEmpty())) {
			
			for (JsLibraryResult jsLibraryResult: jsLibraryResultList) {
				
				str.append(System.getProperty("line.separator"));			
				
				str.append("jsLibraryResult.detectedVersion: " + jsLibraryResult.getDetectedVersion());
				
				str.append(System.getProperty("line.separator"));
				
				str.append("jsLibraryResult.regexRequest: " + jsLibraryResult.getRegexRequest());
				
				str.append(System.getProperty("line.separator"));
				
				str.append("jsLibraryResult.regexResponse: " + jsLibraryResult.getRegexResponse());
				
				JsVulnerability jsVulnerability = jsLibraryResult.getVuln();
				
				if (jsVulnerability!=null) {
					
					str.append(System.getProperty("line.separator"));
					
					str.append("jsLibraryResult.jsVulnerability.atOrAbove: " + jsVulnerability.getAtOrAbove());

					str.append(System.getProperty("line.separator"));
					
					str.append("jsLibraryResult.jsVulnerability.below: " + jsVulnerability.getBelow());

					if ((jsVulnerability.getInfo()!=null)&&(!jsVulnerability.getInfo().isEmpty())) {

						int j = 0;
						
						for (String info: jsVulnerability.getInfo()) {
							
							str.append(System.getProperty("line.separator"));
							
							++j;
							
							str.append("jsLibraryResult.jsVulnerability.info["  + j + "]: " + info);
							
						}
						
					}
					
					if ((jsVulnerability.getIdentifiers()!=null)&&(!jsVulnerability.getIdentifiers().isEmpty())) {
						
						
					}

					str.append(System.getProperty("line.separator"));
					
					str.append("jsLibraryResult.jsVulnerability.severity: " + jsVulnerability.getSeverity());
					
				}
				
			}
		}
		
    }
    
    private String printAPKVulnerableJavaScriptFileLibraryList(List<APKVulnerableJavaScriptFileLibraryList> vulnerableAPKFileScriptLibraries) {

    	StringBuilder str = new StringBuilder();
    	
    	str.append(System.getProperty("line.separator"));
    	
    	str.append(System.getProperty("line.separator"));
    	
    	str.append(System.getProperty("line.separator"));
    	
    	str.append(System.getProperty("line.separator"));
    	
    	str.append(System.getProperty("line.separator"));
    	
    	str.append("Found " + vulnerableAPKFileScriptLibraries.size() + " artifacts with vulnerable JavaScript Libraries...");
    	
    	str.append(System.getProperty("line.separator"));
    	
    	if ((vulnerableAPKFileScriptLibraries!=null)&&(!vulnerableAPKFileScriptLibraries.isEmpty())) {
    		
    		for (APKVulnerableJavaScriptFileLibraryList aPKVulnerableJavaScriptFileLibraryList:vulnerableAPKFileScriptLibraries) {
    			
    			if (str.length()>0) {
    				
    				str.append(System.getProperty("line.separator"));
    				
    				str.append(System.getProperty("line.separator"));
    			}
    			
    			str.append("Scanning " + aPKVulnerableJavaScriptFileLibraryList.getArtifactName());
    			
    			str.append(System.getProperty("line.separator"));
    			
    			str.append("Found vulnerable JavaScript Library: " + aPKVulnerableJavaScriptFileLibraryList.getVulnerableJavaScriptLibraryName() + "...");
    			
    			str.append(System.getProperty("line.separator"));
    			
    		    printVulnerabilitiesResult(aPKVulnerableJavaScriptFileLibraryList.getVulnerabilityList(), str);
    		}

    	}
    	
    	return str.toString();
    }
    
    private void scanAPK(VulnerabilitiesRepository vulnerabilitiesRepository, Resource resource, String baseDirectory, List<APKVulnerableJavaScriptFileLibraryList> vulnerableAPKFileScriptLibraries) throws IOException {
    
        assert resource!=null;
        
        assert baseDirectory!=null;
        
        assert vulnerabilitiesRepository!=null;
        
        String fullyQualifiedFileName = getFullyQualifiedPath(baseDirectory, resource);
        
        ZipFile zip = new ZipFile(fullyQualifiedFileName);
        
        Enumeration<? extends ZipEntry> zipContents = zip.entries();

        while (zipContents.hasMoreElements()) {

        	ZipEntry zipEntry = zipContents.nextElement();
            
            if (zipEntry.getName().endsWith(".js")) {
            	
                String[] javaScriptFileNameParts = zipEntry.getName().split("/");
                
                String javaScriptFileName = null;
                
                if ((javaScriptFileNameParts!=null)&&(javaScriptFileNameParts.length>0)) {
                	
                	javaScriptFileName = javaScriptFileNameParts[javaScriptFileNameParts.length-1];
                }
                
            	InputStream stream = zip.getInputStream(zipEntry);
            	
            	String fileContent = getInputStreamContentAsString(stream);
            	
				List<JsLibraryResult> jsLibraryResultList = vulnerabilitiesRepository.findByFilename(javaScriptFileName);
				
				if ((fileContent!=null)&&((jsLibraryResultList==null)||(jsLibraryResultList.isEmpty()))) {
					
					String sha1Hash = HashUtil.hashSha1(fileContent.getBytes(), 0);
					
					jsLibraryResultList = vulnerabilitiesRepository.findByHash(sha1Hash);
					
				}
				
				if ((fileContent!=null)&&((jsLibraryResultList==null)||(jsLibraryResultList.isEmpty()))) {
					
					jsLibraryResultList = vulnerabilitiesRepository.findByFileContent(fileContent);
					
				}
				
				if ((jsLibraryResultList!=null)&&(!jsLibraryResultList.isEmpty())) {

					APKVulnerableJavaScriptFileLibraryList aPKVulnerableJavaScriptFileLibraryList = new APKVulnerableJavaScriptFileLibraryList();
					
					aPKVulnerableJavaScriptFileLibraryList.setArtifactName(fullyQualifiedFileName);
					
					aPKVulnerableJavaScriptFileLibraryList.setVulnerableJavaScriptLibraryName(zipEntry.getName());
					
					aPKVulnerableJavaScriptFileLibraryList.setVulnerabilityList(jsLibraryResultList);
					
					vulnerableAPKFileScriptLibraries.add(aPKVulnerableJavaScriptFileLibraryList);
					
				}
				
            }
            
        }
        
        zip.close();
        
    }
    
    @Override
    public void execute() throws BuildException {
    	
        assert getBaseDirectory()!=null;
        
        assert getIncludes()!=null;
        
        VulnerabilitiesRepository vulnerabilitiesRepository = null;
        
        DirectoryScanner directoryScanner = new DirectoryScanner();
    	
        if (getIncludes()!=null) {
        	
            directoryScanner.setIncludes(splitAndTrim());    
        }
        
        directoryScanner.setBasedir(new File(getBaseDirectory()));
        
        directoryScanner.scan();
        
        List<APKVulnerableJavaScriptFileLibraryList> vulnerableAPKFileScriptLibraries = new ArrayList<APKVulnerableJavaScriptFileLibraryList>();
        
        String[] files = directoryScanner.getIncludedFiles();
        
        for (int i = 0; i < files.length; i++) {
        	
            Resource resource = directoryScanner.getResource(files[i]);
            
            assert resource!=null;
            
            if (resource!=null && !resource.isDirectory()) {
            	
                try {
                	
                	if (vulnerabilitiesRepository==null) {
                		
                		vulnerabilitiesRepository = getRetireJsVulnerabilitiesRepositoryData();
                		
                		if (vulnerabilitiesRepository==null) {
                			
                			throw new BuildException("Unable to retrieve RetireJs vulnerabilities repository data");
                			
                		}
                		
                	}
                	
                	scanAPK(vulnerabilitiesRepository, resource, getBaseDirectory(), vulnerableAPKFileScriptLibraries);
                	
                }  catch (IOException e) {
                    
                    log(e, Project.MSG_ERR);
                }
                
            }
        	
        }
        
    	String output = printAPKVulnerableJavaScriptFileLibraryList(vulnerableAPKFileScriptLibraries);                	
    	
    	log(output, Project.MSG_INFO);
    	
    }
    
    private String getBaseDirectory() {
        return baseDirectory;
    }

    public void setBaseDirectory(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    private String getIncludes() {
        return includes;
    }

    public void setIncludes(String includes) {
        this.includes = includes;
    }
    
    public static void main(String[] argc) {
        
        String baseDirectory = "C:/eclipse/workspaces_sans/apk-js-lib-vuln-scan-test/sample_data/apk";
        
        String includes = "**\\*.apk";
        
        APKVulnerableJavaScriptLibrariesScanner apkVulnerableJavaScriptLibrariesScanner = new APKVulnerableJavaScriptLibrariesScanner();
        
        apkVulnerableJavaScriptLibrariesScanner.setBaseDirectory(baseDirectory);
        
        apkVulnerableJavaScriptLibrariesScanner.setIncludes(includes);
        
        apkVulnerableJavaScriptLibrariesScanner.execute();
        
    }
	
}
