package com.security.library.filter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class RequestWrapper extends HttpServletRequestWrapper {
	
	private String _body;

	public RequestWrapper(HttpServletRequest request) throws IOException {
		super(request);
		_body = "";
		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(request.getInputStream()));			
		String line;
		while ((line = bufferedReader.readLine()) != null){
			_body += line;
		}
	}

	@Override
	public ServletInputStream getInputStream() throws IOException {
		final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(_body.getBytes());
		return new ServletInputStream() {
			public int read() throws IOException {
				return byteArrayInputStream.read();
			}

			@Override
			public boolean isFinished() {
				return false;
			}

			@Override
			public boolean isReady() {
				return false;
			}

			@Override
			public void setReadListener(ReadListener readListener) {
				
			}
		};
	}

	@Override
	public BufferedReader getReader() throws IOException {
		return new BufferedReader(new InputStreamReader(this.getInputStream()));
	}
}