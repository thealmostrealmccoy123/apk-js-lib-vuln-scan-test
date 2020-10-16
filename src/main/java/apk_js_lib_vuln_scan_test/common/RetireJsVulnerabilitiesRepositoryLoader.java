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
package apk_js_lib_vuln_scan_test.common;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;

import com.h3xstream.retirejs.repo.VulnerabilitiesRepositoryLoader;

/**
 * Extended VulnerabilitiesRepositoryLoader to fix issue with UTF-8 regex version replacement.
 * 
 * @author arm
 *
 */
public class RetireJsVulnerabilitiesRepositoryLoader extends VulnerabilitiesRepositoryLoader {
	
    private String replaceVersion(String regex) {
        
    	regex = regex.replace("Â§Â§versionÂ§Â§","[0-9][0-9.a-z_\\\\\\\\-]+");
    	
    	regex = regex.replace("§§version§§","[0-9][0-9.a-z_\\\\\\\\-]+");
        
        if(regex.contains("{")) {
            regex = regex.replaceAll("\\{\\}", "\\\\{\\\\}");
        }
        
        if(regex.contains("\n")) {
            regex = regex.replaceAll("\n","\\\\n");
        }
        
        return regex;
    }	
	
    public List<String> objToStringList(Object obj, boolean replaceVersionWildcard) {
        JSONArray array = (JSONArray) obj;
        List<String> strArray = new ArrayList<String>(array.length());
        for (int i = 0; i < array.length(); i++) { //Build Vulnerabilities list

            if (replaceVersionWildcard) {
                strArray.add(replaceVersion(array.getString(i)));
            } else {
                strArray.add(array.getString(i));
            }
        }
        return strArray;
    }
	
}