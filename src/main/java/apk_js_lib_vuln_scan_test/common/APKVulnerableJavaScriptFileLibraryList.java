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

import java.util.List;

import com.h3xstream.retirejs.repo.JsLibraryResult;

/**
 * POJO to summarize vulnerable JavaScript libraries in scanned APK.
 * 
 * @author arm
 *
 */
public class APKVulnerableJavaScriptFileLibraryList {

	private String artifactName;

	private String vulnerableJavaScriptLibraryName;

	private List<JsLibraryResult> vulnerabilityList;

	public String getArtifactName() {
		return artifactName;
	}

	public void setArtifactName(String artifactName) {
		this.artifactName = artifactName;
	}

	public String getVulnerableJavaScriptLibraryName() {
		return vulnerableJavaScriptLibraryName;
	}

	public void setVulnerableJavaScriptLibraryName(String vulnerableJavaScriptLibraryName) {
		this.vulnerableJavaScriptLibraryName = vulnerableJavaScriptLibraryName;
	}

	public List<JsLibraryResult> getVulnerabilityList() {
		return vulnerabilityList;
	}

	public void setVulnerabilityList(List<JsLibraryResult> vulnerabilityList) {
		this.vulnerabilityList = vulnerabilityList;
	}
    	
}
