package study.security.config.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import study.security.config.auth.PrincipalDetails;
import study.security.config.oauth.provider.GoogleUserInfo;
import study.security.config.oauth.provider.NaverUserInfo;
import study.security.config.oauth.provider.OAuth2UserInfo;
import study.security.model.User;
import study.security.repository.UserRepository;

import java.util.Map;
import java.util.Optional;


@RequiredArgsConstructor
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>)oAuth2User.getAttributes().get("response"));
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("환영");
        String email = oAuth2UserInfo.getEmail();
        String role = "USER";

        Optional<User> findUser = userRepository.findByUsername(username);
        User user = new User();

        if (findUser.isEmpty()) {
            user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(user);
            return new PrincipalDetails(user,oAuth2User.getAttributes());
        }
        System.out.println("이미 회원가입이 되어있습니다.");
        return new PrincipalDetails(findUser.get(),oAuth2User.getAttributes());
    }
}
