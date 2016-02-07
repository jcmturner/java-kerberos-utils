package uk.co.jtnet.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

public class IdentityTest {
	
	Identity testId;
	String username = "testusername";
	String realm = "testrealm";
	String displayName = "Test User";
	String group1 = "testGroup1";
	String group2 = "testGroup2";
	List<String> groups = Arrays.asList(group1, group2);
	String role1 = "testRole1";
	String role2 = "testRole2";
	List<String> roles = Arrays.asList(role1, role2);
	private static String object1 = "testObj1";
	private static String object2 = "testObj2";
	
	private static final Map<String, Object> attributes;
    static
    {
    	attributes = new HashMap<String, Object>();
    	attributes.put("a1", object1);
    	attributes.put("a2", object2);
    }
	
	@Before
	public void createIdentity(){
		testId = new Identity();
	}

	@Test
	public void usernameTest() {
		testId.setUsername(username);
		assertEquals(username, testId.getUsername());
	}
	
	@Test
	public void realmTest() {
		testId.setRealm(realm);
		assertEquals(realm, testId.getRealm());
	}
	
	@Test
	public void displayNameTest() {
		testId.setDisplayName(displayName);
		assertEquals(displayName, testId.getDisplayName());
	}
	
	@Test
	public void groupsTest() {
		testId.addGroup(group1);
		testId.addGroup(group2);
		assertTrue(testId.getGroups().contains(group1));
		assertTrue(testId.getGroups().contains(group2));
		testId.removeGroup(group1);
		testId.removeGroup(group2);
		assertFalse(testId.getGroups().contains(group1));
		assertFalse(testId.getGroups().contains(group2));
	}
	
	@Test
	public void rolesTest() {
		testId.addRole(role1);
		testId.addRole(role2);
		assertTrue(testId.getRoles().contains(role1));
		assertTrue(testId.getRoles().contains(role2));
		testId.removeRole(role1);
		testId.removeRole(role2);
		assertFalse(testId.getRoles().contains(role1));
		assertFalse(testId.getRoles().contains(role2));
	}
	
	@Test
	public void attributesTest() {
		testId.addAttribute("a1", object1);
		testId.addAttribute("a2", object2);
		assertTrue(testId.getAttributes().containsKey("a1"));
		assertTrue(testId.getAttributes().containsKey("a2"));
		assertTrue(testId.getAttributes().containsValue(object1));
		assertTrue(testId.getAttributes().containsValue(object1));
		assertEquals(testId.getAttribute("a1"), object1);
		assertEquals(testId.getAttribute("a2"), object2);
		testId.removeAttribute("a1");
		testId.removeAttribute("a2");
		assertFalse(testId.getAttributes().containsKey("a1"));
		assertFalse(testId.getAttributes().containsKey("a2"));
		assertFalse(testId.getAttributes().containsValue(object1));
		assertFalse(testId.getAttributes().containsValue(object1));
		Map<String, Object> mapToAdd = new HashMap<String, Object>();
		mapToAdd.put("a1", object1);
		mapToAdd.put("a2", object2);
		testId.addAllAttributes(mapToAdd);
		assertTrue(testId.getAttributes().containsKey("a1"));
		assertTrue(testId.getAttributes().containsKey("a2"));
		assertTrue(testId.getAttributes().containsValue(object1));
		assertTrue(testId.getAttributes().containsValue(object1));
		assertEquals(testId.getAttribute("a1"), object1);
		assertEquals(testId.getAttribute("a2"), object2);
		
	}

}
