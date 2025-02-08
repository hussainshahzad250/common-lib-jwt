package com.hussain.response;


import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@NoArgsConstructor
public class Response {
	private HttpStatus status;
	private int code;
	private String message = "Please try Later";
	private Object responseObject;


	public Response(String message, Object responseObject, HttpStatus status) {
		this.message = message;
		this.status = status;
		this.code = status.value();
		this.responseObject = responseObject;
	}

	public Response(String message, HttpStatus status) {
		this.message = message;
		this.status = status;
		this.code = status.value();
	}

	public Response(String message, HttpStatus status, HttpStatus code) {
		this.message = message;
		this.status = status;
		this.code = code.value();
	}
}
