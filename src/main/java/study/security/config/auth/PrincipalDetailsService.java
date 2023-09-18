package study.security.config.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import study.security.model.User;
import study.security.repository.UserRepository;


// SecurityConfig에서 loginProcessingUrl("/login")으로 설정되어
// /login으로 요청이 왔을때 자동으로 스프링 컨테이너에서 UserDetailsService타입으로 등록된 객체에서
//  loadUserByUsername메서드를 실행

@RequiredArgsConstructor
@Service
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("해당 사용자가 존재하지 않습니다 : " + username));
        return new PrincipalDetails(user);
    }
}
