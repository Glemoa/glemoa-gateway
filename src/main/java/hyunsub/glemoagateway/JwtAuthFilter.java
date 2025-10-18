package hyunsub.glemoagateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthFilter implements GlobalFilter {
    @Value("${jwt.secretKey}")
    private String secretKey;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private final List<String> ALLOWED_PATHS = List.of(
                // ⭐️ member 서비스 인증 불필요 API 경로 추가 ⭐️
                "/member/doSave",
                "/member/doLogin",
                "/member/refreshToken",

                // ⭐️ read 서비스 인증 불필요 API 경로 추가 ⭐️
                "/recent-posts",             // @GetMapping("/recent-posts")
                "/today-recommended-posts",  // @GetMapping("/today-recommended-posts")
                "/today-view-count-posts",  // @GetMapping("/today-view-count-posts")
                "/search-posts",
                "/search-today-recommended-posts",
                "/search-today-view-count-posts",
                // 쿼리 파라미터 (?source=...)는 경로에 포함하지 않음

                // ⭐️ viewCountRank 서비스 인증 불필요 API 경로 추가 ⭐️
                "/ranks/daily", // GET /ranks/daily (정확히 일치)
                "/views/**"     // GET /views/{postId} & POST /views/{postId} (접두사 매칭)
            );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // token 검증
        System.out.println("token 검증 시작");
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        String path = exchange.getRequest().getURI().getRawPath();
        System.out.println(path);

        // 인증이 필요 없는 경로는 필터를 통과 -> 그 다음 체인으로 이동해라. 라는 코드이다.
        if (ALLOWED_PATHS.stream().anyMatch(allowed -> pathMatcher.match(allowed, path))) {
            System.out.println("인증 X 경로 검증 필터 생략");
            return chain.filter(exchange);
        }

        try {
            if(bearerToken == null || !bearerToken.startsWith("Bearer ")) {
                throw new IllegalArgumentException("token 관련 예외 발생");
            }

            String accessToken = bearerToken.substring(7);

            System.out.println(accessToken);

            // token 검증 및 claims 추출
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();

            String userId = claims.getSubject();
            String email = claims.get("email", String.class);
            String role = claims.get("role", String.class);

            // 헤더에 X-User-Id변수로 id값 추가 및 ROLE 추가
            // X를 붙이는 것은 custom header라는 것을 의미하는 널리 쓰이는 관례
            ServerWebExchange modifiedExchange = exchange.mutate()
                    .request(builder -> builder
                            .header("X-User-Id", userId)
                            .header("X-User-Email", email)
                            .header("X-User-Role", role) // 역할 추가
                    )
                    .build();

            System.out.println("유효한 accessToken 입니다! ");

            return chain.filter(modifiedExchange);
        } catch (Exception e){
            e.printStackTrace();
            /*
                클라이언트에게 보낼 HTTP 응답 코드를 **401 Unauthorized**로 설정합니다.
                이는 "인증이 필요하거나 유효하지 않은 인증 정보를 사용했다"는 것을 의미합니다.
             */
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            /*
                현재 요청에 대한 처리를 즉시 종료하고, 설정된 응답(401)을 클라이언트에게 보냅니다.
                이 시점에서 게이트웨이 필터 체인의 뒷단 필터나 실제 목적지 서비스(API)로는 요청이 전달되지 않습니다.
             */
            return exchange.getResponse().setComplete();
        }
    }
}
