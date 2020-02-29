package in.aboutaakash.springsecurity.resource;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainResource {
	
	@GetMapping("/")
	public String home() {
		return "<h1>Welcome</h1>";
	}

}
